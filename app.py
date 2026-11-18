import os, re, sqlite3, hashlib, secrets, time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "mexxa.db"
PROFILE_DIR = ROOT / "profiles"
PROFILE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("MEXXA_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # 256 KB per upload
ADMIN_TOKEN = os.environ.get("MEXXA_ADMIN_TOKEN", "")
ALLOWED_EXT = {".conf", ".txt", ".json"}
COUNTRIES = [
    ("🇸🇬", "Singapore"), ("🇮🇳", "India"), ("🇧🇷", "Brazil"),
    ("🇩🇪", "Germany"), ("🇳🇱", "Netherlands"), ("🇺🇸", "United States"),
    ("🇯🇵", "Japan"), ("🇹🇷", "Turkey")
]

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def now_ts():
    return int(time.time())

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_hash TEXT UNIQUE NOT NULL,
          key_hint TEXT NOT NULL,
          duration_seconds INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER,
          revoked INTEGER NOT NULL DEFAULT 0,
          note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS activations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_hash TEXT NOT NULL,
          activated_at INTEGER NOT NULL,
          event TEXT NOT NULL,
          detail TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          filename TEXT NOT NULL,
          stored_name TEXT UNIQUE NOT NULL,
          country TEXT NOT NULL,
          uploaded_at INTEGER NOT NULL
        );
        """)
init_db()

def hash_key(value):
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()

def record(key_hash, event, detail=""):
    with db() as con:
        con.execute("INSERT INTO activations(key_hash, activated_at, event, detail) VALUES(?,?,?,?)",
                    (key_hash, now_ts(), event, detail[:180]))

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapped

def active_key():
    key_hash = session.get("key_hash")
    if not key_hash:
        return None
    with db() as con:
        row = con.execute("SELECT * FROM keys WHERE key_hash=?", (key_hash,)).fetchone()
    if not row or row["revoked"]:
        session.pop("key_hash", None)
        return None
    if row["expires_at"] and row["expires_at"] <= now_ts():
        return None
    return row

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw = request.form.get("key", "").strip()
        if not raw or len(raw) > 100:
            flash("Введите корректный KEY.", "error")
            return redirect(url_for("index"))
        digest = hash_key(raw)
        with db() as con:
            row = con.execute("SELECT * FROM keys WHERE key_hash=?", (digest,)).fetchone()
            if not row or row["revoked"]:
                record(digest, "failed", "invalid_or_revoked")
                flash("KEY недействителен или отозван.", "error")
                return redirect(url_for("index"))
            if row["expires_at"] and row["expires_at"] <= now_ts():
                record(digest, "expired")
                flash("Срок действия KEY истёк.", "error")
                return redirect(url_for("index"))
            if row["expires_at"] is None:
                expiry = now_ts() + row["duration_seconds"]
                con.execute("UPDATE keys SET expires_at=? WHERE key_hash=?", (expiry, digest))
        session["key_hash"] = digest
        record(digest, "activated")
        return redirect(url_for("dashboard"))
    if active_key():
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    row = active_key()
    if not row:
        session.pop("key_hash", None)
        return redirect(url_for("index"))
    with db() as con:
        profiles = con.execute("SELECT * FROM profiles ORDER BY uploaded_at DESC").fetchall()
    remaining = max(0, row["expires_at"] - now_ts()) if row["expires_at"] else row["duration_seconds"]
    return render_template("dashboard.html", key_hint=row["key_hint"], remaining=remaining,
                           profiles=profiles, countries=COUNTRIES)

@app.route("/logout")
def logout():
    if session.get("key_hash"):
        record(session["key_hash"], "logout")
    session.pop("key_hash", None)
    return redirect(url_for("index"))

@app.route("/profiles/<int:profile_id>")
def download_profile(profile_id):
    if not active_key():
        return redirect(url_for("index"))
    with db() as con:
        row = con.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not row:
        abort(404)
    return send_from_directory(PROFILE_DIR, row["stored_name"], as_attachment=True,
                               download_name=row["filename"])

@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    with db() as con:
        keys = con.execute("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100").fetchall()
        events = con.execute("SELECT * FROM activations ORDER BY activated_at DESC LIMIT 100").fetchall()
        profiles = con.execute("SELECT * FROM profiles ORDER BY uploaded_at DESC").fetchall()
    return render_template("admin.html", keys=keys, events=events, profiles=profiles)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not ADMIN_TOKEN:
            flash("Сначала задайте MEXXA_ADMIN_TOKEN в Termux.", "error")
        elif secrets.compare_digest(request.form.get("token", ""), ADMIN_TOKEN):
            session["is_admin"] = True
            return redirect(url_for("admin"))
        else:
            flash("Неверный токен.", "error")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

@app.route("/admin/revoke/<int:key_id>", methods=["POST"])
@admin_required
def revoke_key(key_id):
    with db() as con:
        row = con.execute("SELECT key_hash FROM keys WHERE id=?", (key_id,)).fetchone()
        if row:
            con.execute("UPDATE keys SET revoked=1 WHERE id=?", (key_id,))
            record(row["key_hash"], "revoked", "admin")
    flash("KEY отозван.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/upload", methods=["POST"])
@admin_required
def upload_profile():
    upload = request.files.get("profile")
    country = request.form.get("country", "Unspecified")
    if not upload or not upload.filename:
        flash("Выберите файл профиля.", "error")
        return redirect(url_for("admin"))
    filename = secure_filename(upload.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        flash("Разрешены только .conf, .txt и .json.", "error")
        return redirect(url_for("admin"))
    content = upload.read(256 * 1024 + 1)
    if len(content) > 256 * 1024:
        flash("Файл слишком большой (лимит 256 KB).", "error")
        return redirect(url_for("admin"))
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        flash("Файл должен быть текстовым UTF-8.", "error")
        return redirect(url_for("admin"))
    if not text.strip():
        flash("Пустой файл не принимается.", "error")
        return redirect(url_for("admin"))
    stored = secrets.token_hex(16) + ext
    (PROFILE_DIR / stored).write_bytes(content)
    with db() as con:
        con.execute("INSERT INTO profiles(filename, stored_name, country, uploaded_at) VALUES(?,?,?,?)",
                    (filename, stored, country[:60], now_ts()))
    flash("Профиль добавлен. Он доступен пользователям с активным KEY.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/delete-profile/<int:profile_id>", methods=["POST"])
@admin_required
def delete_profile(profile_id):
    with db() as con:
        row = con.execute("SELECT stored_name FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if row:
            try: (PROFILE_DIR / row["stored_name"]).unlink(missing_ok=True)
            except OSError: pass
            con.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
    flash("Профиль удалён.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(413)
def too_large(_):
    flash("Загрузка слишком большая.", "error")
    return redirect(url_for("admin"))

if __name__ == "__main__":
    # Local-only by default. Use a trusted reverse proxy for public hosting.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
