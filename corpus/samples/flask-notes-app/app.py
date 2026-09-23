import sqlite3
from functools import wraps

from flask import Flask, g, jsonify, redirect, request, session, url_for
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "notes-app-dev-key-2024"
CORS(app)

DATABASE = "notes.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password)),
    )
    db.commit()
    return jsonify({"status": "registered"})


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        session["user_id"] = user["id"]
        return jsonify({"status": "ok"})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok"})


@app.route("/notes", methods=["GET"])
@login_required
def list_notes():
    db = get_db()
    rows = db.execute(
        "SELECT id, title, body FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/notes", methods=["POST"])
@login_required
def create_note():
    title = request.form["title"]
    body = request.form["body"]
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (session["user_id"], title, body),
    )
    db.commit()
    return jsonify({"status": "created"}), 201


@app.route("/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    title = request.form["title"]
    body = request.form["body"]
    db = get_db()
    db.execute(
        "UPDATE notes SET title = ?, body = ? WHERE id = ?", (title, body, note_id)
    )
    db.commit()
    return jsonify({"status": "updated"})


@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return jsonify({"status": "deleted"})


@app.route("/search", methods=["GET"])
@login_required
def search_notes():
    term = request.args.get("q", "")
    db = get_db()
    query = f"SELECT id, title, body FROM notes WHERE user_id = {session['user_id']} AND title LIKE '%{term}%'"
    rows = db.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/users", methods=["GET"])
@login_required
def admin_users():
    db = get_db()
    rows = db.execute("SELECT id, username FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=True)
