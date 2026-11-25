
from flask import Flask, request, render_template, redirect, make_response, session
from markupsafe import Markup, escape
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "hardcoded-dev-secret")  # intentionally weak

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return render_template("index.html")

MAX_QUERY_LEN = 100

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        # Passwords stored in plaintext (intentionally bad)
        row = cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
        if row and row["password"] == password:
            session["user_id"] = row["id"]
            resp = make_response(redirect("/profile"))
            # Missing security flags intentionally
            return resp
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", user=user)

if __name__ == "__main__":
    # Fix #4 (CWE-94): debugger disabled by default, local bind by default
    app.run(
        host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_RUN_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
