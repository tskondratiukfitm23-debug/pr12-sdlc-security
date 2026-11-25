import os
import pathlib
import sqlite3

from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")

# Fix #5 (CWE-256): passwords are stored only as salted scrypt hashes.
# Demo credentials can be overridden via environment variables.
DEMO_USERS = [
    ("alice", os.environ.get("DEMO_ALICE_PASSWORD", "alice123")),
    ("bob", os.environ.get("DEMO_BOB_PASSWORD", "bob12345")),
]

pathlib.Path(DB_PATH).unlink(missing_ok=True)
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.executescript(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL
    );
    INSERT INTO posts(title, body) VALUES
        ('Welcome', 'This is a demo post.'),
        ('Security Tips', 'Never trust user input. Use parameterized queries.');
    """
)
cur.executemany(
    "INSERT INTO users(username, password_hash) VALUES (?, ?)",
    [(u, generate_password_hash(p, method="scrypt")) for u, p in DEMO_USERS],
)
conn.commit()
conn.close()
print(f"Initialized SQLite DB at {DB_PATH}")
