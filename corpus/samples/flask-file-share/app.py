import os
import uuid

import boto3
from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from models import Upload, User, db

app = Flask(__name__)
app.secret_key = "fileshare"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://fileshare:s3cr3t-pw@localhost/fileshare"
db.init_app(app)

AWS_ACCESS_KEY_ID = "AKIAQ4XZ7NLPWJ3MTKVD"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
BUCKET = "fileshare-uploads"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)


def login_required(view):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper


@app.route("/signup", methods=["POST"])
def signup():
    user = User(
        email=request.form["email"],
        password_hash=generate_password_hash(request.form["password"]),
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"status": "created"}), 201


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user and check_password_hash(user.password_hash, request.form["password"]):
        session["user_id"] = user.id
        return jsonify({"status": "ok"})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files["file"]
    key = f"{uuid.uuid4()}-{uploaded.filename}"
    s3.upload_fileobj(uploaded, BUCKET, key)
    record = Upload(user_id=session["user_id"], key=key, name=uploaded.filename)
    db.session.add(record)
    db.session.commit()
    return jsonify({"link": f"/download/{key}"})


@app.route("/download/<path:key>", methods=["GET"])
def download(key):
    url = s3.generate_presigned_url(
        "get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=3600
    )
    return jsonify({"url": url})


@app.route("/uploads", methods=["GET"])
@login_required
def list_uploads():
    records = Upload.query.filter_by(user_id=session["user_id"]).all()
    return jsonify([{"key": r.key, "name": r.name} for r in records])


@app.route("/uploads/<int:upload_id>", methods=["DELETE"])
def delete_upload(upload_id):
    record = Upload.query.get(upload_id)
    s3.delete_object(Bucket=BUCKET, Key=record.key)
    db.session.delete(record)
    db.session.commit()
    return jsonify({"status": "deleted"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
