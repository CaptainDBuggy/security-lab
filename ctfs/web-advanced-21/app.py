"""
Gridlock — Advanced Web CTF  (challenge 21)

Three-flag chain using three distinct vulnerability classes:
Mass assignment  →  Insecure deserialization (Pickle)  →  Second-order SQLi

1. POST /api/register accepts JSON and stores all provided fields,
   including 'role'. The frontend only sends username + password, but
   adding "role":"admin" in the request body grants admin access.
   /admin shows flag1.                                                      (flag1)

2. Admin panel has an "Import Board Data" feature that base64-decodes
   user input and passes it to pickle.loads(). Craft a malicious pickle
   that calls open('/flag2.txt').read(). The deserialized result is
   returned in the response.                                                (flag2)

3. The admin "User Activity" page fetches a user record by ID (safe),
   then uses the stored username in a string-formatted SQL query
   (unsafe). Register an account whose username is a UNION SELECT
   payload, then trigger the query from the admin activity page.            (flag3)

Fixes:
 - Registration: explicitly whitelist accepted fields. Never pass
   request data directly into a model or query.
 - Import: never use pickle on untrusted data. Use JSON or a schema-
   validated format.
 - Activity: use parameterized queries for ALL database operations,
   including those using previously-stored data.
"""

from flask import Flask, request, jsonify, session, redirect
import sqlite3, secrets, os, base64, pickle

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB = "/tmp/gridlock.db"
FLAG1 = "FLAG{m4ss_4ss1gnm3nt_r0l3_esc4l4t10n}"

os.makedirs("/app", exist_ok=True)
with open("/flag2.txt", "w") as f:
    f.write("FLAG{p1ckl3_d3s3r14l1z4t10n_rc3}\n\n"
            "Hint for flag 3:\n"
            "The final flag is stored in the database.\n"
            "Table: secrets  |  Column: value\n"
            "The admin user-activity page queries issues by stored username.\n"
            "What if a username contained SQL?\n")
with open("/flag3.txt", "w") as f:
    f.write("This is a decoy. Flag 3 is in the database, not on disk.\n")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = get_db()
    conn.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS issues;
        DROP TABLE IF EXISTS secrets;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer'
        );
        CREATE TABLE issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            assignee TEXT,
            status TEXT DEFAULT 'open'
        );
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL
        );
    """)

    admin_pass = secrets.token_hex(16)
    conn.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                 ("admin", admin_pass, "admin"))

    issues = [
        ("Fix login timeout", "Session expires too quickly on mobile",
         "admin", "open"),
        ("Redesign board view", "Cards need drag-and-drop sorting",
         "admin", "in-progress"),
        ("Add CSV export", "Export issue list as CSV from project settings",
         "admin", "open"),
        ("Audit logging", "Track all admin actions for compliance",
         "admin", "backlog"),
    ]
    for title, desc, assignee, status in issues:
        conn.execute(
            "INSERT INTO issues (title, description, assignee, status) "
            "VALUES (?,?,?,?)", (title, desc, assignee, status))

    conn.execute("INSERT INTO secrets (key, value) VALUES (?,?)",
                 ("flag3", "FLAG{s3c0nd_0rd3r_sql_1nj3ct10n}"))
    conn.execute("INSERT INTO secrets (key, value) VALUES (?,?)",
                 ("db_password", "internal-" + secrets.token_hex(8)))

    conn.commit()
    conn.close()


init()


# ── Shared HTML ─────────────────────────────────────────────────

STYLE = (
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#0a0a0a;"
    "color:#c8c8c8;padding:2rem}"
    "h1{color:#cc3355;margin-bottom:.3rem}"
    ".sub{color:#555;margin-bottom:1.5rem}"
    "nav{margin-bottom:2rem}"
    "nav a{color:#cc3355;text-decoration:none;margin-right:1.5rem}"
    "nav a:hover{text-decoration:underline}"
    ".card{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.2rem;margin:.8rem 0}"
    ".card h3{color:#cc3355;font-size:.95rem;margin-bottom:.4rem}"
    ".card p{color:#888;font-size:.85rem;line-height:1.4}"
    "textarea{width:100%;height:140px;background:#080808;color:#c8c8c8;"
    "border:1px solid #333;border-radius:4px;padding:.8rem;"
    "font-family:monospace;font-size:.85rem;resize:vertical}"
    "input[type=text],input[type=password]{width:100%;max-width:360px;"
    "padding:.55rem;background:#080808;color:#c8c8c8;border:1px solid #333;"
    "border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}"
    "label{display:block;color:#666;font-size:.8rem;text-transform:uppercase;"
    "margin-bottom:.2rem;letter-spacing:.04em}"
    "button{background:#cc3355;color:#fff;border:none;padding:.55rem 1.4rem;"
    "border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;"
    "margin-top:.3rem}"
    "button:hover{background:#dd4466}"
    ".result{margin-top:1rem;padding:1rem;background:#080808;"
    "border:1px solid #333;border-radius:4px;white-space:pre-wrap;"
    "font-size:.85rem;display:none}"
    ".muted{color:#444;font-size:.8rem;margin-top:.4rem}"
    ".section{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.5rem;margin:1.5rem 0}"
    ".section h2{color:#cc3355;font-size:1rem;margin-bottom:.8rem}"
    "#msg{margin-top:.8rem;color:#cc3333;font-size:.9rem}"
    ".badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;"
    "font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}"
    ".badge-role{background:#33101a;color:#cc3355;border:1px solid #802040}"
    ".badge-ok{background:#0a3320;color:#33cc66;border:1px solid #196b3a}"
    ".user-row{display:flex;justify-content:space-between;align-items:center;"
    "padding:.6rem 0;border-bottom:1px solid #222}"
    ".user-row:last-child{border-bottom:none}"
    ".user-info{color:#888;font-size:.85rem}"
    ".user-info strong{color:#c8c8c8}"
    ".btn-sm{background:#222;color:#cc3355;border:1px solid #333;"
    "padding:.3rem .8rem;border-radius:3px;cursor:pointer;"
    "font-family:monospace;font-size:.8rem;margin-top:0}"
    ".btn-sm:hover{background:#2a2a2a}"
    "</style>"
)


def nav():
    parts = ['<a href="/">Board</a>']
    if "user" in session:
        parts.append('<a href="/dashboard">Dashboard</a>')
        if session.get("role") == "admin":
            parts.append('<a href="/admin">Admin</a>')
        parts.append(f'<a href="/logout">Logout ({session["user"]})</a>')
    else:
        parts.append('<a href="/login">Login</a>')
        parts.append('<a href="/register">Register</a>')
    return " ".join(parts)


# ── Pages ───────────────────────────────────────────────────────

@app.route("/")
def index():
    conn = get_db()
    issues = conn.execute(
        "SELECT title, status, assignee FROM issues ORDER BY id").fetchall()
    conn.close()
    cards = ""
    for i in issues:
        status_color = "#33cc66" if i["status"] == "open" else "#cc9933"
        cards += (
            f'<div class="card"><h3>{i["title"]}</h3>'
            f'<p>Status: <span style="color:{status_color}">{i["status"]}</span>'
            f' — Assigned to {i["assignee"]}</p></div>')
    return (
        "<!doctype html>"
        "<title>Gridlock — Issue Tracker</title>"
        f"{STYLE}"
        "<h1>Gridlock</h1>"
        '<p class="sub">Project Issue Tracker</p>'
        f"<nav>{nav()}</nav>"
        f"{cards}"
    )


@app.route("/register")
def register_page():
    return (
        "<!doctype html>"
        "<title>Gridlock — Register</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Create Account</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doRegister()" style="width:100%">Register</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/login" style="color:#cc3355;text-decoration:none">'
        "Already have an account? Login</a></p></div>"
        "<script>"
        "async function doRegister(){"
        "const r=await fetch('/api/register',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({username:document.getElementById('u').value,"
        "password:document.getElementById('p').value})});"
        "const d=await r.json();"
        "if(d.ok){document.getElementById('msg').style.color='#33cc66';"
        "document.getElementById('msg').textContent='Account created! Redirecting...';"
        "setTimeout(()=>window.location='/login',1000);}"
        "else document.getElementById('msg').textContent=d.error;}"
        "</script>"
    )


@app.route("/login")
def login_page():
    return (
        "<!doctype html>"
        "<title>Gridlock — Login</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Gridlock Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/register" style="color:#cc3355;text-decoration:none">'
        "Need an account? Register</a></p></div>"
        "<script>"
        "async function doLogin(){"
        "const r=await fetch('/api/login',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({username:document.getElementById('u').value,"
        "password:document.getElementById('p').value})});"
        "const d=await r.json();"
        "if(d.ok) window.location='/dashboard';"
        "else document.getElementById('msg').textContent=d.error;}"
        "</script>"
    )


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return (
        "<!doctype html>"
        "<title>Gridlock — Dashboard</title>"
        f"{STYLE}"
        "<h1>Dashboard</h1>"
        f'<p class="sub">{session["user"]} '
        f'<span class="badge badge-role">{session.get("role", "")}</span></p>'
        f"<nav>{nav()}</nav>"
        '<div class="section">'
        "<h2>Your Issues</h2>"
        '<p class="muted">No issues assigned to you yet.</p>'
        "</div>"
        '<div class="section">'
        "<h2>Access Level</h2>"
        f'<p>Role: <strong>{session.get("role", "viewer")}</strong></p>'
        '<p class="muted">Viewers can browse the board. '
        "Admin access is required for imports, user management, "
        "and activity auditing.</p>"
        "</div>"
    )


@app.route("/admin")
def admin_page():
    if session.get("role") != "admin":
        return jsonify(ok=False, error="admin role required"), 403
    return (
        "<!doctype html>"
        "<title>Gridlock — Admin</title>"
        f"{STYLE}"
        "<h1>Admin Panel</h1>"
        '<p class="sub">System administration</p>'
        f"<nav>{nav()}</nav>"

        '<div class="section">'
        "<h2>Admin Access Granted</h2>"
        f'<p style="color:#33cc66;font-size:1.1rem;margin-bottom:.5rem">'
        f"{FLAG1}</p>"
        '<p class="muted">Registration accepted additional fields beyond '
        "what the form sends.</p></div>"

        '<div class="section">'
        "<h2>Import Board Data</h2>"
        '<p class="muted">Import serialized board data. Paste base64-encoded '
        "export data below.</p>"
        '<textarea id="imp" spellcheck="false" '
        'placeholder="Paste base64-encoded board data here..."></textarea>'
        '<button onclick="doImport()">Import</button>'
        '<div id="imp-out" class="result"></div></div>'

        '<div class="section">'
        "<h2>Registered Users</h2>"
        '<div id="user-list">Loading...</div></div>'

        '<div class="section">'
        "<h2>User Activity</h2>"
        '<p class="muted">View issues assigned to a user. '
        "Select a user above or enter an ID.</p>"
        '<label>User ID</label>'
        '<input id="uid" type="text" placeholder="2" style="max-width:120px">'
        '<button onclick="doActivity()">View Activity</button>'
        '<div id="act-out" class="result"></div></div>'

        "<script>"
        "fetch('/api/admin/users').then(r=>r.json()).then(d=>{"
        "const el=document.getElementById('user-list');el.innerHTML='';"
        "d.users.forEach(u=>{"
        "el.innerHTML+='<div class=\"user-row\">"
        "<span class=\"user-info\"><strong>'+u.username+'</strong>"
        " ('+u.role+')</span>"
        "<button class=\"btn-sm\" onclick=\"viewUser('+u.id+')\">Activity</button>"
        "</div>';});});"
        "function viewUser(id){document.getElementById('uid').value=id;doActivity();}"
        "async function doImport(){"
        "const r=await fetch('/api/import',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({data:document.getElementById('imp').value})});"
        "const d=await r.json(),el=document.getElementById('imp-out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#33cc66';"
        "el.textContent='Imported: '+JSON.stringify(d.imported);}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "async function doActivity(){"
        "const id=document.getElementById('uid').value;"
        "const r=await fetch('/api/admin/activity/'+id);"
        "const d=await r.json(),el=document.getElementById('act-out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#33cc66';"
        "let txt='User: '+d.user+'\\n\\nAssigned Issues:\\n';"
        "d.issues.forEach(i=>txt+='"
        "  - '+i.title+': '+i.description+'\\n');"
        "if(!d.issues.length) txt+='  (none)';"
        "el.textContent=txt;}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── API ─────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify(ok=False, error="username and password required"), 400
    if len(username) > 80:
        return jsonify(ok=False, error="username too long"), 400

    role = data.get("role", "viewer")

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (username, password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify(ok=False, error="username already taken"), 400
    conn.close()
    return jsonify(ok=True, user=username)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", ""), data.get("password", "")
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (u, p)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False, error="invalid credentials"), 401
    session["user_id"] = row["id"]
    session["user"] = row["username"]
    session["role"] = row["role"]
    return jsonify(ok=True, user=row["username"], role=row["role"])


@app.route("/api/import", methods=["POST"])
def api_import():
    if session.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    data = request.get_json(silent=True) or {}
    payload = data.get("data", "").strip()
    if not payload:
        return jsonify(ok=False, error="data required"), 400
    try:
        raw = base64.b64decode(payload)
        items = pickle.loads(raw)
        if not isinstance(items, list):
            items = [items]
        return jsonify(ok=True, imported=[str(i) for i in items])
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400


@app.route("/api/admin/users")
def api_admin_users():
    if session.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role FROM users ORDER BY id").fetchall()
    conn.close()
    return jsonify(users=[
        {"id": u["id"], "username": u["username"], "role": u["role"]}
        for u in users])


@app.route("/api/admin/activity/<int:user_id>")
def api_admin_activity(user_id):
    if session.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify(ok=False, error="user not found"), 404

    query = (f"SELECT title, description FROM issues "
             f"WHERE assignee = '{user['username']}'")
    try:
        results = conn.execute(query).fetchall()
    except Exception:
        results = []
    conn.close()

    return jsonify(
        ok=True, user=user["username"],
        issues=[{"title": r[0], "description": r[1]} for r in results])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
