from flask import (
    Flask, request, redirect, url_for, session, render_template_string,
    send_from_directory, abort,
)
import hashlib
import json
import sqlite3
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "change-this-secret-before-deployment"
)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # not sent on cross-site POSTs
app.config["SESSION_COOKIE_HTTPONLY"] = True
# On the live (https) site set COOKIE_SECURE=1 so the cookie never travels over http
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Absolute paths: the server may start the app from any folder
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = os.environ.get("TRUSTVAULT_DB", os.path.join(BASE_DIR, "trustvault.db"))
UPLOAD_FOLDER = os.environ.get(
    "TRUSTVAULT_UPLOADS", os.path.join(BASE_DIR, "private_uploads")
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "doc", "docx"}
CATEGORIES = ["Contract", "Salary letter", "Audit", "Drawing", "Other"]
GENESIS = "0" * 64

SMALL = "padding: 6px 12px; font-size: 13px;"
LABEL = "font-weight: 600; font-size: 14px; color: var(--muted);"
SELECT = 'style="width:100%; padding: 12px 14px; margin: 8px 0;"'
RULE = '<hr style="border: 0; border-top: 1px solid var(--line); margin: 24px 0;">'
BACK = '<div style="margin-top: 24px;"><a class="btn" href="{}" style="background: var(--muted);">{}</a></div>'


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def chain_hash(prev, user_id, action, ts):
    """Each audit row is hashed together with the hash of the row before it."""
    payload = json.dumps([prev, user_id, action, ts], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def column_exists(conn, table, column):
    return any(r["name"] == column for r in conn.execute(f"PRAGMA table_info({table})"))


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                category TEXT NOT NULL DEFAULT 'Other',
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                prev_hash TEXT,
                hash TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                level TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                UNIQUE (doc_id, user_id),
                FOREIGN KEY (doc_id) REFERENCES documents(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Upgrade an older database in place (keeps all existing data)
        if not column_exists(conn, "users", "role"):
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'")
        if not column_exists(conn, "documents", "category"):
            conn.execute("ALTER TABLE documents ADD COLUMN category TEXT NOT NULL DEFAULT 'Other'")
        if not column_exists(conn, "audit_logs", "hash"):
            conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
            conn.execute("ALTER TABLE audit_logs ADD COLUMN hash TEXT")
            prev = GENESIS
            old = conn.execute(
                "SELECT id, user_id, action, timestamp FROM audit_logs ORDER BY id"
            ).fetchall()
            for r in old:
                h = chain_hash(prev, r["user_id"], r["action"], str(r["timestamp"]))
                conn.execute("UPDATE audit_logs SET prev_hash = ?, hash = ? WHERE id = ?",
                             (prev, h, r["id"]))
                prev = h

        # The audit log can only be added to: edits and deletes are refused by the database
        conn.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs
                        BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""")
        conn.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs
                        BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""")


# --------------------------------------------------------------------------
# Audit trail
# --------------------------------------------------------------------------
def log_event(user_id, action):
    """Add one line to the audit log (refused attempts too), linked to the previous line."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")          # one writer at a time, so the chain never forks
        row = conn.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row and row["hash"] else GENESIS
        conn.execute(
            "INSERT INTO audit_logs (user_id, action, timestamp, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, action, ts, prev, chain_hash(prev, user_id, action, ts))
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def verify_chain():
    """Recompute the whole chain. Returns (ok, rows_checked, first_bad_id, head_hash)."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    prev, checked = GENESIS, 0
    for r in rows:
        expected = chain_hash(prev, r["user_id"], r["action"], str(r["timestamp"]))
        if r["prev_hash"] != prev or r["hash"] != expected:
            return False, checked, r["id"], prev
        prev, checked = r["hash"], checked + 1
    return True, checked, None, prev


# --------------------------------------------------------------------------
# Who is logged in, and what they may do
# --------------------------------------------------------------------------
def current_user():
    """Read from the database on every request, so changes apply immediately."""
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?", (uid,)
        ).fetchone()


def login_required(view):
    """Runs the page only for a logged-in user and hands that user to the page."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            session.clear()
            return redirect(url_for("login"))
        return view(user, *args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(user, *args, **kwargs):
        if user["role"] != "admin":
            log_event(user["id"], f"DENIED_ADMIN_PAGE_{request.path}")
            abort(403)
        return view(user, *args, **kwargs)
    return wrapper


def can_access(doc_id, user_id, need):
    """The ONE place that decides access to a document. need is 'read' or 'edit'.
    Admins get no special access to document contents."""
    with get_db() as conn:
        d = conn.execute("SELECT owner_id FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if d is None:
            return False
        if d["owner_id"] == user_id:
            return True
        p = conn.execute(
            "SELECT level FROM permissions WHERE doc_id = ? AND user_id = ? AND revoked = 0",
            (doc_id, user_id)
        ).fetchone()
    if p is None:
        return False
    return need == "read" or p["level"] == "edit"


# --------------------------------------------------------------------------
# Upload checks and small helpers
# --------------------------------------------------------------------------
def content_ok(ext, head):
    """The first bytes of the file must match the type it claims to be."""
    if ext == "pdf":
        return head.startswith(b"%PDF-")
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "docx":
        return head.startswith(b"PK\x03\x04")
    if ext == "doc":
        return head.startswith(b"\xd0\xcf\x11\xe0")
    return ext == "txt" and b"\x00" not in head


def check_upload(f):
    """Returns (clean_name, extension, error_message)."""
    if not f or not f.filename:
        return None, None, "No file selected."
    name = secure_filename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if not name or ext not in ALLOWED_EXTENSIONS:
        return None, None, "File type not allowed."
    head = f.stream.read(1024)
    f.stream.seek(0)
    if not head:
        return None, None, "The file is empty."
    if not content_ok(ext, head):
        return None, None, "The file content does not match its type."
    return name, ext, None


def like_pattern(text):
    esc = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + esc + "%"


def valid_date(text):
    try:
        datetime.strptime(text, "%Y-%m-%d")
        return text
    except ValueError:
        return ""


def category_options(selected=None, any_option=False):
    out = '<option value="">Any category</option>' if any_option else ""
    for c in CATEGORIES:
        out += f'<option{" selected" if c == selected else ""}>{c}</option>'
    return out


def table(headers, rows):
    head = "".join(f"<th>{h}</th>" for h in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"


def link(href, text, style=""):
    return f'<a class="btn" style="{SMALL} {style}" href="{href}">{text}</a>'


def post_button(action, text, style="", confirm=""):
    ask = f" onsubmit=\"return confirm('{confirm}');\"" if confirm else ""
    return (f'<form method="POST" action="{action}" style="margin:0;"{ask}>'
            f'<button type="submit" class="btn" style="{SMALL} {style}">{text}</button></form>')


def actions_cell(*items):
    return ('<td style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">'
            + "".join(items) + "</td>")


PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>TrustVault</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="card">
        <h1>TrustVault</h1>
        <h2>{{ heading }}</h2>
        {% if message %}
            <div class="flash {% if error %}error{% elif success %}success{% endif %}">{{ message }}</div>
        {% endif %}
        {{ content|safe }}
    </div>
</body>
</html>
"""


def page(heading, content, message="", error=False, success=False):
    return render_template_string(
        PAGE, heading=heading, content=content, message=message,
        error=error, success=success
    )


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------
@app.route("/")
def home():
    user = current_user()
    if not user:
        return page("Secure Document Sharing", """
            <p>Share documents securely and manage access efficiently.</p>
            <div style="margin-top: 20px; display: flex; gap: 10px; justify-content: center;">
                <a class="btn" href="/login">Login</a>
                <a class="btn" href="/register" style="background: var(--muted);">Register</a>
            </div>
        """)

    admin_buttons = ""
    if user["role"] == "admin":
        admin_buttons = (
            '<a class="btn" href="/audit-logs" style="background: var(--brand-dark);">Audit Logs</a>'
            '<a class="btn" href="/admin/users" style="background: var(--brand-dark);">Users</a>'
        )
    return page("Dashboard", f"""
        <p>Welcome, <b>{escape(user['username'])}</b>! You are signed in as <b>{escape(user['role'])}</b>.</p>
        <p>Your documents. Your permissions. Your control.</p>
        <div style="margin-top: 20px; display: flex; gap: 10px; align-items: center; justify-content: center; flex-wrap: wrap;">
            <a class="btn" href="/documents">My Documents</a>
            {admin_buttons}
            <form method="POST" action="/logout" style="margin:0;">
                <button type="submit" style="background: var(--bad);">Logout</button>
            </form>
        </div>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        if role not in ("owner", "viewer"):      # nobody can make themselves admin
            role = "viewer"

        if not username or not email or not password:
            message = "Please fill in every field."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username, email, password_hash, role) "
                        "VALUES (?, ?, ?, ?)",
                        (username, email, generate_password_hash(password), role)
                    )
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                message = "Username or email already exists."

    return page("Create Account", f"""
        <form method="POST">
            <input name="username" placeholder="Username" required>
            <input name="email" type="email" placeholder="Email Address" required>
            <input name="password" type="password"
                   placeholder="Password (min 8 characters)" minlength="8" required>
            <select name="role" {SELECT}>
                <option value="viewer">I will read documents shared with me</option>
                <option value="owner">I will upload and share my own documents</option>
            </select>
            <button type="submit">Create Account</button>
        </form>
        <p style="margin-top: 16px;">Already registered? <a href="/login">Login</a></p>
    """, message, error=bool(message))


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event(user["id"], "SUCCESSFUL_LOGIN")
            return redirect(url_for("home"))

        log_event(user["id"] if user else None, "FAILED_LOGIN")
        message = "Invalid email or password."

    return page("Login", """
        <form method="POST">
            <input name="email" type="email" placeholder="Email Address" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="margin-top: 16px;">New user? <a href="/register">Register</a></p>
    """, message, error=bool(message))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------
@app.route("/documents", methods=["GET", "POST"])
@login_required
def documents(user):
    message, success = "", False

    if request.method == "POST":
        # Only owners may upload. Viewers and admins are refused (and it is logged).
        if user["role"] != "owner":
            log_event(user["id"], "DENIED_UPLOAD_NOT_OWNER_ROLE")
            abort(403)

        category = request.form.get("category", "")
        name, ext, problem = check_upload(request.files.get("document"))
        if category not in CATEGORIES:
            message = "Choose a category."
        elif problem:
            log_event(user["id"], "DENIED_UPLOAD_INVALID_FILE")
            message = problem
        else:
            stored = f"{uuid.uuid4().hex}.{ext}"
            request.files["document"].save(os.path.join(UPLOAD_FOLDER, stored))
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO documents (filename, stored_name, owner_id, category) "
                    "VALUES (?, ?, ?, ?)", (name, stored, user["id"], category)
                )
            log_event(user["id"], f"UPLOAD_FILE_{name}")
            message, success = "Document uploaded successfully!", True

    # ---- search filters (values are passed as parameters, never pasted into SQL)
    q = request.args.get("q", "").strip()[:100]
    owner = request.args.get("owner", "").strip()[:100]
    category_f = request.args.get("category", "")
    date_from = valid_date(request.args.get("from", ""))
    date_to = valid_date(request.args.get("to", ""))

    where, args = "", {"uid": user["id"]}
    if q:
        where += " AND d.filename LIKE :q ESCAPE '\\'"
        args["q"] = like_pattern(q)
    if owner:
        where += " AND u.username LIKE :owner ESCAPE '\\'"
        args["owner"] = like_pattern(owner)
    if category_f in CATEGORIES:
        where += " AND d.category = :cat"
        args["cat"] = category_f
    if date_from:
        where += " AND substr(d.uploaded_at, 1, 10) >= :df"
        args["df"] = date_from
    if date_to:
        where += " AND substr(d.uploaded_at, 1, 10) <= :dt"
        args["dt"] = date_to

    with get_db() as conn:
        docs = conn.execute(
            "SELECT d.id, d.filename, d.category, d.uploaded_at "
            "FROM documents d JOIN users u ON u.id = d.owner_id "
            "WHERE d.owner_id = :uid" + where + " ORDER BY d.id DESC", args
        ).fetchall()
        shared = conn.execute(
            "SELECT d.id, d.filename, d.category, u.username AS owner, p.level "
            "FROM permissions p JOIN documents d ON d.id = p.doc_id "
            "JOIN users u ON u.id = d.owner_id "
            "WHERE p.user_id = :uid AND p.revoked = 0" + where + " ORDER BY d.id DESC", args
        ).fetchall()

    own_rows = "".join(
        f'<tr><td>{escape(d["filename"])}</td><td>{escape(d["category"])}</td>'
        f'<td>{escape(str(d["uploaded_at"]))}</td>'
        + actions_cell(
            link(f'/verify-download/{d["id"]}', "Download"),
            link(f'/edit/{d["id"]}', "Edit"),
            link(f'/share/{d["id"]}', "Share", "background: var(--brand-dark);"),
            post_button(f'/delete/{d["id"]}', "Delete", "background: var(--bad);",
                        "Are you sure you want to delete this file?"))
        + "</tr>"
        for d in docs
    )
    items = (table(["Filename", "Category", "Uploaded At", "Action"], own_rows)
             if docs else "<p style='margin-top: 16px;'>No documents found.</p>")

    shared_rows = "".join(
        f'<tr><td>{escape(s["filename"])}</td><td>{escape(s["category"])}</td>'
        f'<td>{escape(s["owner"])}</td><td>{escape(s["level"])}</td>'
        + actions_cell(
            link(f'/verify-download/{s["id"]}', "Download"),
            link(f'/edit/{s["id"]}', "Edit") if s["level"] == "edit" else "")
        + "</tr>"
        for s in shared
    )
    shared_items = (table(["Filename", "Category", "Owner", "Your access", "Action"], shared_rows)
                    if shared else "<p style='margin-top: 16px;'>Nothing shared with you matches.</p>")

    upload_form = ""
    if user["role"] == "owner":
        upload_form = f"""
        <form method="POST" enctype="multipart/form-data">
            <label style="{LABEL}">Upload New Document:</label>
            <input type="file" name="document" required style="background: #fafafa;">
            <select name="category" {SELECT}>{category_options()}</select>
            <button type="submit">Upload Document</button>
        </form>
        {RULE}
        """

    return page("My Documents", f"""
        {upload_form}
        <form method="GET">
            <label style="{LABEL}">Search documents:</label>
            <input name="q" placeholder="File name" value="{escape(q)}">
            <input name="owner" placeholder="Owner username" value="{escape(owner)}">
            <select name="category" {SELECT}>{category_options(category_f, any_option=True)}</select>
            <label style="{LABEL}">From:</label>
            <input type="date" name="from" value="{escape(date_from)}">
            <label style="{LABEL}">To:</label>
            <input type="date" name="to" value="{escape(date_to)}">
            <button type="submit">Search</button>
            <a class="btn" href="/documents" style="background: var(--muted);">Clear</a>
        </form>
        {RULE}
        <h3 style="font-size: 16px; margin-bottom: 8px;">Your Files</h3>
        {items}
        {RULE}
        <h3 style="font-size: 16px; margin-bottom: 8px;">Shared With Me</h3>
        {shared_items}
        {BACK.format("/", "Back to Dashboard")}
    """, message, error=bool(message) and not success, success=success)


@app.route("/share/<int:doc_id>", methods=["GET", "POST"])
@login_required
def share(user, doc_id):
    # Only the OWNER may share. Anyone else gets a plain 404.
    with get_db() as conn:
        d = conn.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?", (doc_id, user["id"])
        ).fetchone()
    if not d:
        log_event(user["id"], f"DENIED_SHARE_DOC_{doc_id}")
        abort(404)

    message, success = "", False

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        level = request.form.get("level", "")
        if level not in ("read", "edit"):
            message = "Choose read or edit."
        else:
            with get_db() as conn:
                target = conn.execute(
                    "SELECT id, username FROM users WHERE email = ?", (email,)
                ).fetchone()
                if target is None:
                    message = "No user with that email."
                elif target["id"] == user["id"]:
                    message = "You already own this document."
                else:
                    conn.execute(
                        "INSERT INTO permissions (doc_id, user_id, level) VALUES (?, ?, ?) "
                        "ON CONFLICT(doc_id, user_id) "
                        "DO UPDATE SET level = excluded.level, revoked = 0",
                        (doc_id, target["id"], level)
                    )
                    message = f"{target['username']} can now {level} this document."
                    success = True
            if success:
                log_event(user["id"],
                          f"GRANT_{level.upper()}_DOC_{doc_id}_TO_{target['username']}")

    with get_db() as conn:
        grants = conn.execute(
            "SELECT users.id, users.username, users.email, permissions.level "
            "FROM permissions JOIN users ON users.id = permissions.user_id "
            "WHERE permissions.doc_id = ? AND permissions.revoked = 0", (doc_id,)
        ).fetchall()

    rows = "".join(
        f'<tr><td>{escape(g["username"])}</td><td>{escape(g["email"])}</td>'
        f'<td>{escape(g["level"])}</td>'
        f'<td>{post_button(f"/revoke/{doc_id}/{g["id"]}", "Remove access", "background: var(--bad);")}</td></tr>'
        for g in grants
    )
    people = (table(["Name", "Email", "Access", ""], rows)
              if grants else "<p style='margin-top: 16px;'>Nobody else has access yet.</p>")

    return page("Share Document", f"""
        <p>Document: <b>{escape(d["filename"])}</b></p>
        <form method="POST">
            <input name="email" type="email" placeholder="Person's email address" required>
            <select name="level" {SELECT}>
                <option value="read">Can read (download)</option>
                <option value="edit">Can read and edit</option>
            </select>
            <button type="submit">Give access</button>
        </form>
        {RULE}
        <h3 style="font-size: 16px; margin-bottom: 8px;">People with access</h3>
        {people}
        {BACK.format("/documents", "Back to Documents")}
    """, message, error=bool(message) and not success, success=success)


@app.route("/revoke/<int:doc_id>/<int:target_id>", methods=["POST"])
@login_required
def revoke(user, doc_id, target_id):
    with get_db() as conn:
        d = conn.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?", (doc_id, user["id"])
        ).fetchone()
    if not d:
        log_event(user["id"], f"DENIED_REVOKE_DOC_{doc_id}")
        abort(404)

    with get_db() as conn:
        conn.execute("UPDATE permissions SET revoked = 1 WHERE doc_id = ? AND user_id = ?",
                     (doc_id, target_id))
    log_event(user["id"], f"REVOKE_DOC_{doc_id}_FROM_USER_{target_id}")
    return redirect(url_for("share", doc_id=doc_id))


@app.route("/edit/<int:doc_id>", methods=["GET", "POST"])
@login_required
def edit_document(user, doc_id):
    if not can_access(doc_id, user["id"], "edit"):
        log_event(user["id"], f"DENIED_EDIT_DOC_{doc_id}")
        abort(404)

    with get_db() as conn:
        d = dict(conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone())

    message, success = "", False

    if request.method == "POST":
        new_name = secure_filename(request.form.get("filename", "").strip())
        new_ext = new_name.rsplit(".", 1)[-1].lower() if "." in new_name else ""
        new_category = request.form.get("category", "")
        f = request.files.get("document")
        stored = d["stored_name"]

        if not new_name or new_ext not in ALLOWED_EXTENSIONS:
            message = "Enter a file name that ends with an allowed type (pdf, txt, png, jpg, jpeg, doc, docx)."
        elif new_category not in CATEGORIES:
            message = "Choose a category."
        else:
            if f and f.filename:
                _name, up_ext, problem = check_upload(f)
                if problem:
                    log_event(user["id"], f"DENIED_EDIT_INVALID_FILE_DOC_{doc_id}")
                    message = problem
                else:
                    stored = f"{uuid.uuid4().hex}.{up_ext}"
                    f.save(os.path.join(UPLOAD_FOLDER, stored))
                    old_path = os.path.join(UPLOAD_FOLDER, d["stored_name"])
                    if os.path.exists(old_path):
                        os.remove(old_path)
            if not message:
                with get_db() as conn:
                    conn.execute(
                        "UPDATE documents SET filename = ?, stored_name = ?, category = ? "
                        "WHERE id = ?", (new_name, stored, new_category, doc_id)
                    )
                log_event(user["id"], f"EDIT_DOC_{doc_id}")
                d["filename"], d["category"] = new_name, new_category
                message, success = "Changes saved.", True

    return page("Edit Document", f"""
        <form method="POST" enctype="multipart/form-data">
            <label style="{LABEL}">File name:</label>
            <input name="filename" value="{escape(d["filename"])}" required>
            <label style="{LABEL}">Category:</label>
            <select name="category" {SELECT}>{category_options(d["category"])}</select>
            <label style="{LABEL}">Replace the file (optional):</label>
            <input type="file" name="document" style="background: #fafafa;">
            <button type="submit">Save changes</button>
        </form>
        {BACK.format("/documents", "Back to Documents")}
    """, message, error=bool(message) and not success, success=success)


@app.route("/verify-download/<int:doc_id>", methods=["GET", "POST"])
@login_required
def verify_download(user, doc_id):
    # owner OR someone who was granted read/edit
    if not can_access(doc_id, user["id"], "read"):
        log_event(user["id"], f"DENIED_DOWNLOAD_DOC_{doc_id}")
        abort(404)

    with get_db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        me = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()

    message = ""
    if request.method == "POST":
        if check_password_hash(me["password_hash"], request.form.get("password", "")):
            session[f"download_auth_{doc_id}"] = True
            log_event(user["id"], f"SUCCESSFUL_DOWNLOAD_FILE_{doc_id}")
            return redirect(url_for("download", doc_id=doc_id))
        log_event(user["id"], f"FAILED_DOWNLOAD_PASSWORD_DOC_{doc_id}")
        message = "Incorrect password. Security verification failed."

    return page("Security Check", f"""
        <p>Security check required to download: <b>{escape(d["filename"])}</b></p>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter your account password" required>
            <button type="submit">Verify & Download</button>
        </form>
        {BACK.format("/documents", "Cancel")}
    """, message, error=bool(message))


@app.route("/download/<int:doc_id>")
@login_required
def download(user, doc_id):
    # Checked again on every download, so removing access works at once
    if not can_access(doc_id, user["id"], "read"):
        session.pop(f"download_auth_{doc_id}", None)
        log_event(user["id"], f"DENIED_DOWNLOAD_DOC_{doc_id}")
        abort(404)

    auth_key = f"download_auth_{doc_id}"
    if not session.get(auth_key):
        return redirect(url_for("verify_download", doc_id=doc_id))
    session.pop(auth_key, None)

    with get_db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()

    return send_from_directory(UPLOAD_FOLDER, d["stored_name"],
                               as_attachment=True, download_name=d["filename"])


@app.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete_document(user, doc_id):
    with get_db() as conn:
        d = conn.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?", (doc_id, user["id"])
        ).fetchone()
    if not d:
        log_event(user["id"], f"DENIED_DELETE_DOC_{doc_id}")
        abort(404)

    file_path = os.path.join(UPLOAD_FOLDER, d["stored_name"])
    if os.path.exists(file_path):
        os.remove(file_path)
    with get_db() as conn:
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.execute("DELETE FROM permissions WHERE doc_id = ?", (doc_id,))
    log_event(user["id"], f"SUCCESSFUL_DELETE_FILE_{doc_id}")
    return redirect(url_for("documents"))


# --------------------------------------------------------------------------
# Admin: sees activity and users, never document contents
# --------------------------------------------------------------------------
def audit_page(message="", error=False, success=False):
    who = request.args.get("who", "").strip()[:100]
    action = request.args.get("action", "").strip()[:60]
    refused_only = request.args.get("refused") == "1"
    sql = ("SELECT a.id, u.username, a.action, a.timestamp "
           "FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id WHERE 1 = 1")
    args = {}
    if who:
        sql += " AND u.username LIKE :who ESCAPE '\\'"
        args["who"] = like_pattern(who)
    if action:
        sql += " AND a.action LIKE :action ESCAPE '\\'"
        args["action"] = like_pattern(action)
    if refused_only:
        sql += " AND (a.action LIKE 'DENIED%' OR a.action LIKE 'FAILED%')"
    sql += " ORDER BY a.id DESC LIMIT 300"

    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        logs = conn.execute(sql, args).fetchall()
        suspicious = conn.execute(
            "SELECT u.username, COUNT(*) AS n "
            "FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id "
            "WHERE (a.action LIKE 'DENIED%' OR a.action LIKE 'FAILED%') AND a.timestamp >= ? "
            "GROUP BY a.user_id HAVING n >= 3", (since,)
        ).fetchall()

    alerts = "".join(
        f'<div class="flash error">{escape(s["username"] or "Unknown visitor")} '
        f'was refused or failed {s["n"]} times in the last 24 hours.</div>'
        for s in suspicious
    )
    rows = "".join(
        f'<tr><td>{r["id"]}</td><td>{escape(r["username"] or "Unknown")}</td>'
        f'<td>{escape(r["action"])}</td><td>{escape(str(r["timestamp"]))}</td></tr>'
        for r in logs
    )
    log_table = (table(["ID", "User", "Action", "Timestamp (UTC)"], rows)
                 if logs else "<p style='margin-top:16px;'>No audit logs found.</p>")

    return page("Audit Logs", f"""
        {alerts}
        <form method="POST" action="/audit-logs/verify" style="margin: 0 0 16px;">
            <button type="submit">Check that the log has not been altered</button>
        </form>
        <form method="GET">
            <input name="who" placeholder="Username" value="{escape(who)}">
            <input name="action" placeholder="Action (e.g. DOWNLOAD, GRANT, DENIED)" value="{escape(action)}">
            <label style="{LABEL}">
                <input type="checkbox" name="refused" value="1" {"checked" if refused_only else ""}
                       style="width:auto; margin-right: 8px;">Only refused / failed
            </label>
            <button type="submit">Filter</button>
        </form>
        {RULE}
        {log_table}
        {BACK.format("/", "Back to Dashboard")}
    """, message, error, success)


@app.route("/audit-logs")
@admin_required
def view_audit_logs(user):
    return audit_page()


@app.route("/audit-logs/verify", methods=["POST"])
@admin_required
def verify_audit_logs(user):
    ok, checked, bad_id, head = verify_chain()
    if ok:
        return audit_page(f"Audit log is intact: {checked} entries verified. "
                          f"Latest fingerprint: {head}", success=True)
    return audit_page(f"AUDIT LOG TAMPERED: the chain breaks at entry {bad_id} "
                      f"(after {checked} valid entries).", error=True)


@app.route("/admin/users")
@admin_required
def admin_users(user):
    with get_db() as conn:
        users = conn.execute("SELECT id, username, email, role FROM users ORDER BY id").fetchall()
    rows = "".join(
        f'<tr><td>{u["id"]}</td><td>{escape(u["username"])}</td>'
        f'<td>{escape(u["email"])}</td><td>{escape(u["role"])}</td></tr>'
        for u in users
    )
    return page("Users", table(["ID", "Username", "Email", "Role"], rows)
                + BACK.format("/", "Back to Dashboard"))


@app.errorhandler(403)
def forbidden(e):
    return page("Not allowed", '<a class="btn" href="/">Back to Dashboard</a>',
                "You do not have permission to do that.", error=True), 403


@app.errorhandler(413)
def too_large(e):
    return page("My Documents", '<a class="btn" href="/documents">Back</a>',
                "File too large (max 5 MB allowed).", error=True), 413


def make_admin(email):
    """Command line only:  python app.py make-admin someone@example.com
    Nobody can become admin through the website, which is the point."""
    email = email.strip().lower()
    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            sys.exit("No account with that email. Register it on the website first.")
        conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user["id"],))
    log_event(None, "ADMIN_ROLE_GRANTED_TO_" + email)
    print(email, "is now an admin.")


# Create the tables whenever the app loads (also when a web server imports it)
init_db()

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "make-admin":
        make_admin(sys.argv[2])
    else:
        # Debug is OFF unless you ask for it (debug mode lets attackers run code)
        debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
        app.run(debug=debug_mode)