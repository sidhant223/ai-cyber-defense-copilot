import os
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from auth import Principal, get_current_user, require_admin
from db import fetch_all, fetch_one, execute

SECRET_KEY = os.environ["TASKS_SECRET_KEY"]
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://tasks.example.com").split(",")
ACCESS_TOKEN_EXPIRE = timedelta(minutes=30)

limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])

app = FastAPI(title="Tasks")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class Credentials(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(min_length=12, max_length=128)


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=4000)


class TaskPatch(BaseModel):
    done: bool


@app.post("/auth/token")
@limiter.limit("5/minute")
def issue_token(request: Request, credentials: Credentials):
    from auth import authenticate, issue_access_token

    principal = authenticate(credentials.email, credentials.password)
    if principal is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"access_token": issue_access_token(principal, ACCESS_TOKEN_EXPIRE)}


@app.get("/tasks")
def list_tasks(user: Principal = Depends(get_current_user)):
    return fetch_all("SELECT id, title, notes, done FROM tasks WHERE user_id = %s", (user.id,))


@app.post("/tasks", status_code=201)
def create_task(payload: TaskCreate, user: Principal = Depends(get_current_user)):
    execute(
        "INSERT INTO tasks (user_id, title, notes) VALUES (%s, %s, %s)",
        (user.id, payload.title, payload.notes),
    )
    return {"status": "created"}


@app.patch("/tasks/{task_id}")
def patch_task(task_id: int, payload: TaskPatch,
               user: Principal = Depends(get_current_user)):
    execute(
        "UPDATE tasks SET done = %s WHERE id = %s AND user_id = %s",
        (payload.done, task_id, user.id),
    )
    return {"status": "updated"}


@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, user: Principal = Depends(get_current_user)):
    execute("DELETE FROM tasks WHERE id = %s AND user_id = %s", (task_id, user.id))
    return {"status": "deleted"}


@app.get("/admin/users")
def admin_list_users(admin: Principal = Depends(require_admin)):
    return fetch_all("SELECT id, email, role FROM users")


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, admin: Principal = Depends(require_admin)):
    execute("DELETE FROM users WHERE id = %s", (user_id,))
    return JSONResponse({"status": "deleted"})


@app.get("/health")
def health():
    return {"status": "ok"}
