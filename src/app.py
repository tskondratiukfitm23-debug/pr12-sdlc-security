import hmac
import logging
import os
import secrets
import sqlite3
import time

from flask import Flask, abort, redirect, render_template, request, session
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Fix #6 (CWE-798): secret only from environment, no hardcoded fallback
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY environment variable is required")
app.secret_key = _secret

# SESS-1: hardened session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")
MAX_QUERY_LEN = 100
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60

# LOG-1: security audit log
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
audit = logging.getLogger("audit")

_failed = {}  # username -> (count, first_failure_ts); in-memory demo store


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# CSRF-1 (#8): per-session token, checked on every POST
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            audit.warning("csrf_rejected ip=%s path=%s", request.remote_addr, request.path)
            abort(400)


# HDR-1 (#9): security headers on every response
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Server"] = "app"
    return resp


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/echo")
def echo():
    # Fix #3 (CWE-79): user input is HTML-escaped before output
    msg = escape(request.args.get("msg", "")[:MAX_QUERY_LEN])
    return Markup("<h1>Echo</h1><p>{}</p>").format(msg)


@app.route("/search")
def search():
    # Fix #2 (CWE-89): parameterized query + input length limit
    q = request.args.get("q", "")[:MAX_QUERY_LEN]
    pattern = f"%{q}%"
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, title, body FROM posts WHERE title LIKE ? OR body LIKE ?",
        (pattern, pattern),
    ).fetchall()
    # Fix #10 (CWE-200): SQL text is no longer passed to the template
    return render_template("search.html", q=q, rows=rows)


def _locked(username):
    count, first = _failed.get(username, (0, 0.0))
    if count >= MAX_FAILED_LOGINS and time.time() - first < LOCKOUT_SECONDS:
        return True
    if time.time() - first >= LOCKOUT_SECONDS:
        _failed.pop(username, None)
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")[:64]
        password = request.form.get("password", "")
        if _locked(username):
            audit.warning("login_locked user=%s ip=%s", username, request.remote_addr)
            return render_template("login.html", error="Invalid credentials"), 429
        conn = get_db()
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        # Fix #5 (CWE-256/307): salted scrypt hash check + lockout
        if row and check_password_hash(row["password_hash"], password):
            _failed.pop(username, None)
            session.clear()  # prevent session fixation
            session["user_id"] = row["id"]
            audit.info("login_success user=%s ip=%s", username, request.remote_addr)
            return redirect("/profile")
        count, first = _failed.get(username, (0, time.time()))
        _failed[username] = (count + 1, first)
        audit.warning("login_failed user=%s ip=%s attempt=%d", username, request.remote_addr, count + 1)
        return render_template("login.html", error="Invalid credentials"), 401
    return render_template("login.html")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    user = conn.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", user=user)


if __name__ == "__main__":
    # Fix #4 (CWE-94): debugger disabled by default, local bind by default
    app.run(
        host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_RUN_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
