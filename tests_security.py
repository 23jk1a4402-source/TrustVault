"""Automated security tests for TrustVault.

Run from the project folder:   python -m pytest -q
They use a temporary database, so your real data is never touched.
"""
import io
import os
import sqlite3
import sys
import tempfile
import uuid

_tmp = tempfile.mkdtemp()
os.environ["TRUSTVAULT_DB"] = os.path.join(_tmp, "test.db")
os.environ["TRUSTVAULT_UPLOADS"] = os.path.join(_tmp, "uploads")
os.environ["FLASK_SECRET_KEY"] = "test-secret-key"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app1  # noqa: E402

PASSWORD = "password123"


def db():
    return sqlite3.connect(app1.DB_NAME)


def new_user(role="owner"):
    """Register + log in a brand new user. Returns (client, username, email)."""
    name = "u" + uuid.uuid4().hex[:8]
    email = name + "@test.com"
    c = app1.app.test_client()
    c.post("/register", data={"username": name, "email": email,
                              "password": PASSWORD, "role": role})
    c.post("/login", data={"email": email, "password": PASSWORD})
    return c, name, email


def new_admin():
    c, name, email = new_user("viewer")
    conn = db()
    conn.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    return c, name, email


def user_id(email):
    conn = db()
    row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row[0]


def upload(c, filename="plan.txt", content=b"top secret", category="Contract"):
    c.post("/documents", data={"document": (io.BytesIO(content), filename),
                               "category": category},
           content_type="multipart/form-data")
    conn = db()
    row = conn.execute("SELECT id FROM documents WHERE filename = ? ORDER BY id DESC",
                       (filename,)).fetchone()
    conn.close()
    return row[0] if row else None


def download(c, doc_id):
    """The full download flow: password check, then the file."""
    r = c.get(f"/download/{doc_id}")
    if r.status_code == 302:
        c.post(f"/verify-download/{doc_id}", data={"password": PASSWORD})
        r = c.get(f"/download/{doc_id}")
    return r


def audit_has(fragment):
    conn = db()
    n = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE ?",
                     ("%" + fragment + "%",)).fetchone()[0]
    conn.close()
    return n > 0


# ---- 1. nobody gets in without logging in ------------------------------------
def test_anonymous_visitors_are_sent_to_login():
    anon = app1.app.test_client()
    for path in ("/documents", "/audit-logs", "/admin/users", "/share/1",
                 "/edit/1", "/download/1", "/verify-download/1"):
        r = anon.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"], path


# ---- 2. one user cannot reach another user's documents -----------------------
def test_stranger_cannot_download_edit_share_or_delete():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "private-a.txt")
    stranger, _, _ = new_user("owner")
    assert stranger.get(f"/verify-download/{doc}").status_code == 404
    assert download(stranger, doc).status_code == 404
    assert stranger.get(f"/edit/{doc}").status_code == 404
    assert stranger.post(f"/edit/{doc}", data={"filename": "x.txt", "category": "Other"}).status_code == 404
    assert stranger.get(f"/share/{doc}").status_code == 404
    assert stranger.post(f"/delete/{doc}").status_code == 404
    assert stranger.post(f"/revoke/{doc}/1").status_code == 404


def test_refused_attempts_are_in_the_audit_log():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "private-b.txt")
    stranger, _, _ = new_user("owner")
    stranger.get(f"/verify-download/{doc}")
    assert audit_has(f"DENIED_DOWNLOAD_DOC_{doc}")


def test_admin_cannot_read_document_contents():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "private-c.txt")
    admin, _, _ = new_admin()
    assert download(admin, doc).status_code == 404


# ---- 3. roles -----------------------------------------------------------------
def test_viewer_cannot_upload():
    viewer, _, _ = new_user("viewer")
    r = viewer.post("/documents", data={"document": (io.BytesIO(b"hello"), "v.txt"),
                                         "category": "Other"},
                    content_type="multipart/form-data")
    assert r.status_code == 403


def test_nobody_can_register_as_admin():
    c = app1.app.test_client()
    email = "mallory" + uuid.uuid4().hex[:6] + "@test.com"
    c.post("/register", data={"username": email[:12], "email": email,
                              "password": PASSWORD, "role": "admin"})
    conn = db()
    role = conn.execute("SELECT role FROM users WHERE email = ?", (email,)).fetchone()[0]
    conn.close()
    assert role in ("owner", "viewer")


def test_only_admin_can_open_audit_log_and_user_list():
    for role in ("owner", "viewer"):
        c, _, _ = new_user(role)
        assert c.get("/audit-logs").status_code == 403
        assert c.get("/admin/users").status_code == 403
        assert c.post("/audit-logs/verify").status_code == 403
    admin, _, _ = new_admin()
    assert admin.get("/audit-logs").status_code == 200
    assert admin.get("/admin/users").status_code == 200


# ---- 4. grants, edit rights and immediate revoke ----------------------------
def test_read_grant_then_revoke_works_immediately():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "shared-d.txt", b"hello bob")
    bob, _, bob_email = new_user("viewer")
    assert download(bob, doc).status_code == 404
    owner.post(f"/share/{doc}", data={"email": bob_email, "level": "read"})
    r = download(bob, doc)
    assert r.status_code == 200 and r.data == b"hello bob"
    assert bob.get(f"/edit/{doc}").status_code == 404          # read only
    owner.post(f"/revoke/{doc}/{user_id(bob_email)}")
    assert bob.get(f"/download/{doc}").status_code == 404       # same session, no re-login
    assert bob.get(f"/verify-download/{doc}").status_code == 404


def test_edit_grant_allows_editing_but_not_deleting_or_sharing():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "shared-e.txt")
    helper, _, helper_email = new_user("owner")
    owner.post(f"/share/{doc}", data={"email": helper_email, "level": "edit"})
    assert helper.get(f"/edit/{doc}").status_code == 200
    r = helper.post(f"/edit/{doc}", data={"filename": "renamed.txt", "category": "Audit"})
    assert r.status_code == 200 and b"Changes saved" in r.data
    assert helper.post(f"/delete/{doc}").status_code == 404
    assert helper.get(f"/share/{doc}").status_code == 404


# ---- 5. the audit trail ------------------------------------------------------
def test_grant_and_revoke_are_recorded():
    owner, _, _ = new_user("owner")
    doc = upload(owner, "shared-f.txt")
    _, _, other_email = new_user("viewer")
    owner.post(f"/share/{doc}", data={"email": other_email, "level": "read"})
    owner.post(f"/revoke/{doc}/{user_id(other_email)}")
    assert audit_has(f"GRANT_READ_DOC_{doc}_TO_")
    assert audit_has(f"REVOKE_DOC_{doc}_FROM_USER_")


def test_audit_log_refuses_edits_and_deletes():
    new_user("owner")
    conn = db()
    for sql in ("UPDATE audit_logs SET action = 'x'", "DELETE FROM audit_logs"):
        try:
            conn.execute(sql)
            assert False, "the database should have refused: " + sql
        except sqlite3.DatabaseError:
            pass
    conn.close()


def test_tampering_with_the_audit_log_is_detected():
    new_user("owner")
    assert app1.verify_chain()[0] is True
    conn = db()
    first = conn.execute("SELECT id, action FROM audit_logs ORDER BY id LIMIT 1").fetchone()
    # an attacker with file access removes the safety trigger and rewrites history
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_logs SET action = 'FORGED' WHERE id = ?", (first[0],))
    conn.commit()
    ok, _, bad_id, _ = app1.verify_chain()
    assert ok is False and bad_id == first[0]
    # put everything back so the other tests are not affected
    conn.execute("UPDATE audit_logs SET action = ? WHERE id = ?", (first[1], first[0]))
    conn.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs "
                 "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END")
    conn.commit()
    conn.close()
    assert app1.verify_chain()[0] is True


# ---- 6. search never leaks ---------------------------------------------------
def test_search_only_returns_documents_you_may_see():
    secret = "zebra" + uuid.uuid4().hex[:6] + ".txt"
    owner, owner_name, _ = new_user("owner")
    upload(owner, secret, category="Audit")
    stranger, _, _ = new_user("owner")
    assert secret.encode() not in stranger.get("/documents?q=zebra").data
    assert secret.encode() not in stranger.get(f"/documents?owner={owner_name}").data
    assert secret.encode() in owner.get("/documents?q=zebra").data
    assert secret.encode() in owner.get("/documents?category=Audit").data
    assert secret.encode() not in owner.get("/documents?category=Contract").data
    assert secret.encode() not in owner.get("/documents?from=2999-01-01").data
    assert owner.get("/documents?q=%27%20OR%201%3D1--").status_code == 200   # injection text is harmless


# ---- 7. uploads are checked --------------------------------------------------
def test_fake_and_forbidden_files_are_rejected():
    owner, _, _ = new_user("owner")
    assert upload(owner, "fake.pdf", b"MZ\x90\x00 this is really a program") is None
    assert upload(owner, "run.exe", b"hello") is None
    assert upload(owner, "empty.txt", b"") is None
    assert upload(owner, "good.pdf", b"%PDF-1.4 ok") is not None


# ---- 8. passwords ------------------------------------------------------------
def test_passwords_are_stored_hashed_and_wrong_password_fails():
    _, _, email = new_user("owner")
    conn = db()
    stored = conn.execute("SELECT password_hash FROM users WHERE email = ?", (email,)).fetchone()[0]
    conn.close()
    assert stored != PASSWORD and ":" in stored
    c = app1.app.test_client()
    c.post("/login", data={"email": email, "password": "wrong-password"})
    assert c.get("/documents").status_code == 302