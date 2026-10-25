import sqlite3

# read-only: this cannot change or damage your data
c = sqlite3.connect("file:trustvault.db?mode=ro", uri=True)

queries = {
    "users": "SELECT id, username, email FROM users",
    "documents": "SELECT id, filename, owner_id, uploaded_at FROM documents",
    "permissions": "SELECT * FROM permissions",
    "audit_logs": "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30",
}

for name, sql in queries.items():
    print("\n=== " + name + " ===")
    try:
        cur = c.execute(sql)
        print([d[0] for d in cur.description])
        for row in cur:
            print(tuple(row))
    except Exception as e:
        print("error:", e)