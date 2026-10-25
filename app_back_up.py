from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Development only: set a private secret key before deployment
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "change-this-secret-before-deployment"
)

DB_NAME = "trustvault.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)


PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>TrustVault</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: white;
            text-align: center;
            padding: 60px 20px;
        }
        .card {
            max-width: 420px;
            margin: auto;
            padding: 30px;
            background: #1e293b;
            border-radius: 16px;
        }
        h1 { color: #60a5fa; }
        input {
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            border: 1px solid #64748b;
        }
        button, .link {
            display: inline-block;
            padding: 11px 18px;
            margin: 8px 4px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            text-decoration: none;
            cursor: pointer;
        }
        p { color: #cbd5e1; }
        .message { color: #fbbf24; }
    </style>
</head>
<body>
    <div class="card">
        <h1>TrustVault</h1>
        <h2>{{ heading }}</h2>
        {% if message %}
            <p class="message">{{ message }}</p>
        {% endif %}
        {{ content|safe }}
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    if "user_id" in session:
        content = f"""
            <p>Welcome, {session['username']}!</p>
            <p>Your documents. Your permissions. Your control.</p>
            <a class="link" href="/logout">Logout</a>
        """
        return render_template_string(
            PAGE, heading="Dashboard", content=content, message=""
        )

    content = """
        <p>Share documents securely and manage access.</p>
        <a class="link" href="/register">Register</a>
        <a class="link" href="/login">Login</a>
    """
    return render_template_string(
        PAGE, heading="Secure Document Sharing",
        content=content, message=""
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            message = "Please fill in every field."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            password_hash = generate_password_hash(password)

            try:
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO users
                           (username, email, password_hash)
                           VALUES (?, ?, ?)""",
                        (username, email, password_hash)
                    )
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                message = "Username or email already exists."

    content = """
        <form method="POST">
            <input name="username" placeholder="Username" required>
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password"
                   placeholder="Password (minimum 8 characters)"
                   minlength="8" required>
            <button type="submit">Create Account</button>
        </form>
        <p>Already registered? <a href="/login">Login</a></p>
    """
    return render_template_string(
        PAGE, heading="Create Account", content=content, message=message
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("home"))

        message = "Invalid email or password."

    content = """
        <form method="POST">
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password"
                   placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p>New user? <a href="/register">Register</a></p>
    """
    return render_template_string(
        PAGE, heading="Login", content=content, message=message
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)