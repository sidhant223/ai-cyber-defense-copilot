import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db import fetch_one

SECRET_KEY = os.environ["TASKS_SECRET_KEY"]
ALGORITHM = "HS256"

hasher = PasswordHasher()
bearer = HTTPBearer(auto_error=True)


@dataclass(frozen=True)
class Principal:
    id: int
    email: str
    role: str


def hash_password(raw: str) -> str:
    return hasher.hash(raw)


def authenticate(email: str, raw_password: str) -> Principal | None:
    row = fetch_one(
        "SELECT id, email, role, password_hash FROM users WHERE email = %s", (email,)
    )
    if row is None:
        return None
    try:
        hasher.verify(row["password_hash"], raw_password)
    except VerifyMismatchError:
        return None
    return Principal(id=row["id"], email=row["email"], role=row["role"])


def issue_access_token(principal: Principal, expires_delta: timedelta) -> str:
    payload = {
        "sub": str(principal.id),
        "role": principal.role,
        "exp": datetime.now(timezone.utc) + expires_delta,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> Principal:
    try:
        claims = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="not authenticated")
    row = fetch_one("SELECT id, email, role FROM users WHERE id = %s", (claims["sub"],))
    if row is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return Principal(id=row["id"], email=row["email"], role=row["role"])


def require_admin(user: Principal = Depends(get_current_user)) -> Principal:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="forbidden")
    return user
