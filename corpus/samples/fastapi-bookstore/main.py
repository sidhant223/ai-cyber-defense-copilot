import hashlib
import sqlite3
import subprocess
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI(title="Bookshop stock")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "bookshop-token-secret"
DB = "stock.db"


class Book(BaseModel):
    isbn: str
    title: str
    author: str
    stock: int
    price: float


class StockUpdate(BaseModel):
    stock: int


def connect():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_current_user(token: str = Depends(oauth2_scheme)):
    conn = connect()
    row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return row["username"]


@app.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = connect()
    digest = hashlib.md5(form.password.encode()).hexdigest()
    user = conn.execute(
        "SELECT * FROM staff WHERE username = ? AND password_hash = ?",
        (form.username, digest),
    ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = hashlib.sha256(f"{form.username}{datetime.now()}".encode()).hexdigest()
    conn.execute(
        "INSERT INTO sessions (username, token) VALUES (?, ?)", (form.username, token)
    )
    conn.commit()
    return {"access_token": token, "token_type": "bearer"}


@app.get("/books")
def list_books():
    conn = connect()
    rows = conn.execute("SELECT * FROM books").fetchall()
    return [dict(r) for r in rows]


@app.get("/books/{isbn}")
def get_book(isbn: str):
    conn = connect()
    row = conn.execute("SELECT * FROM books WHERE isbn = ?", (isbn,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.post("/books")
def add_book(book: Book, user: str = Depends(get_current_user)):
    conn = connect()
    conn.execute(
        "INSERT INTO books (isbn, title, author, stock, price) VALUES (?, ?, ?, ?, ?)",
        (book.isbn, book.title, book.author, book.stock, book.price),
    )
    conn.commit()
    return {"status": "created"}


@app.patch("/books/{isbn}")
def update_stock(isbn: str, update: StockUpdate):
    conn = connect()
    conn.execute("UPDATE books SET stock = ? WHERE isbn = ?", (update.stock, isbn))
    conn.commit()
    return {"status": "updated"}


@app.delete("/books/{isbn}")
def delete_book(isbn: str):
    conn = connect()
    conn.execute("DELETE FROM books WHERE isbn = ?", (isbn,))
    conn.commit()
    return {"status": "deleted"}


@app.get("/export")
def export_catalogue(destination: str, user: str = Depends(get_current_user)):
    conn = connect()
    rows = conn.execute("SELECT * FROM books").fetchall()
    with open("/tmp/catalogue.csv", "w") as handle:
        for row in rows:
            handle.write(",".join(str(v) for v in tuple(row)) + "\n")
    subprocess.run(f"cp /tmp/catalogue.csv {destination}", shell=True)
    return {"status": "exported", "destination": destination}
