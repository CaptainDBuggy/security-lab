"""
Archivex — Intermediate Web CTF  (challenge 18)

Three-flag chain using three distinct vulnerability classes:
IDOR  →  XXE  →  Python code injection (eval)

1. GET /api/docs returns total:5 but only 3 public docs. GET /api/docs/4
   has no auth check — read restricted doc 4 for flag 1 + service-account
   creds + the import endpoint path.                                        (flag1)

2. Log in as svc-import. POST /api/import with XML containing a SYSTEM
   entity -> file:///app/config.ini -> flag 2 + admin password.             (flag2)

3. Log in as admin. POST /api/calc with a Python expression — eval() runs
   it with a keyword blocklist. open('/flag3.txt').read() bypasses the
   filter.                                                                  (flag3)

Fixes:
 - /api/docs/<id>: enforce ownership / role check on restricted docs.
 - /api/import: use defusedxml or XMLParser(resolve_entities=False).
 - /api/calc: never use eval() on user input; use ast.literal_eval() or
   a safe expression parser.
"""

from flask import Flask, request, jsonify, session, redirect
from lxml import etree
import sqlite3, secrets, os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB = "/tmp/archivex.db"
ADMIN_PASS = secrets.token_hex(16)
SVC_USER = "svc-import"
SVC_PASS = "BulkUpload!2026"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = get_db()
    conn.executescript("""
        DROP TABLE IF EXISTS docs;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS records;
        CREATE TABLE docs (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            restricted INTEGER DEFAULT 0
        );
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            body TEXT
        );
    """)

    conn.execute("INSERT INTO users VALUES (?,?,?)",
                 ("admin", ADMIN_PASS, "admin"))
    conn.execute("INSERT INTO users VALUES (?,?,?)",
                 (SVC_USER, SVC_PASS, "user"))

    docs = [
        (1, "Q3 Revenue Summary",
         "Quarterly revenue reached $4.2M, up 12% from Q2. Key growth "
         "drivers include enterprise licensing and the professional "
         "services expansion into APAC markets. Operating margins held "
         "steady at 18%.", 0),

        (2, "Employee Onboarding Guide",
         "Welcome aboard! First-week checklist: collect your badge from "
         "reception, complete security-awareness training in the LMS, "
         "request system access through the IT portal, and join #general "
         "and your team channel on Slack.", 0),

        (3, "Office IT Policy",
         "All employees must use company-approved hardware. VPN enrollment "
         "is mandatory for remote access. Report security incidents to "
         "security@archivex.internal within 24 hours. Unapproved software "
         "installations are prohibited.", 0),

        (4, "Data Import Service — Setup Guide",
         "INTERNAL — DO NOT DISTRIBUTE\n\n"
         "FLAG{1d0r_br0k3n_4cc3ss_c0ntr0l}\n\n"
         "The bulk data import service accepts XML at POST /api/import.\n"
         "Required format:\n\n"
         "<records>\n"
         "  <record>\n"
         "    <title>Document Title</title>\n"
         "    <body>Content here</body>\n"
         "  </record>\n"
         "</records>\n\n"
         "Authentication required. Service account for automated imports:\n"
         f"  Username: {SVC_USER}\n"
         f"  Password: {SVC_PASS}\n\n"
         "Contact data-ops@ with questions.", 1),

        (5, "Infrastructure Notes",
         "INTERNAL — server configuration notes.\n\n"
         "The admin panel at /admin includes a metric expression evaluator "
         "for computing ad-hoc calculations. Expressions are evaluated "
         "server-side.\n\n"
         "Service configuration is stored at /app/config.ini. The admin "
         "password is rotated on each container restart.", 1),
    ]
    for d in docs:
        conn.execute("INSERT INTO docs VALUES (?,?,?,?)", d)

    conn.commit()
    conn.close()

    os.makedirs("/app", exist_ok=True)
    with open("/app/config.ini", "w") as f:
        f.write("[archivex]\n")
        f.write("app_name = Archivex\n")
        f.write(f"admin_password = {ADMIN_PASS}\n")
        f.write("flag2 = FLAG{xxe_f1l3_r34d_c0nf1g_3xf1l}\n")
        f.write(f"db_path = {DB}\n")


init()


# ── Shared HTML ──────────────────────────────────────────────

STYLE = (
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#0a0a0a;"
    "color:#c8c8c8;padding:2rem}"
    "h1{color:#00cc66;margin-bottom:.3rem}"
    ".sub{color:#555;margin-bottom:1.5rem}"
    "nav{margin-bottom:2rem}"
    "nav a{color:#00cc66;text-decoration:none;margin-right:1.5rem}"
    "nav a:hover{text-decoration:underline}"
    ".card{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.2rem;margin:.8rem 0}"
    ".card h3{color:#00cc66;font-size:.95rem;margin-bottom:.4rem}"
    ".card p{color:#888;font-size:.85rem;line-height:1.4}"
    "textarea{width:100%;height:180px;background:#080808;color:#c8c8c8;"
    "border:1px solid #333;border-radius:4px;padding:.8rem;"
    "font-family:monospace;font-size:.85rem;resize:vertical}"
    "input[type=text],input[type=password]{width:100%;max-width:360px;"
    "padding:.55rem;background:#080808;color:#c8c8c8;border:1px solid #333;"
    "border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}"
    "label{display:block;color:#666;font-size:.8rem;text-transform:uppercase;"
    "margin-bottom:.2rem;letter-spacing:.04em}"
    "button{background:#00cc66;color:#000;border:none;padding:.55rem 1.4rem;"
    "border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;"
    "margin-top:.3rem}"
    "button:hover{background:#00ff80}"
    ".result{margin-top:1rem;padding:1rem;background:#080808;"
    "border:1px solid #333;border-radius:4px;white-space:pre-wrap;"
    "font-size:.85rem;display:none}"
    ".muted{color:#444;font-size:.8rem;margin-top:.4rem}"
    ".section{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.5rem;margin:1.5rem 0}"
    ".section h2{color:#00cc66;font-size:1rem;margin-bottom:.8rem}"
    "#msg{margin-top:.8rem;color:#cc3333;font-size:.9rem}"
    "</style>"
)


def nav():
    parts = ['<a href="/">Archive</a>']
    if "user" in session:
        parts.append('<a href="/dashboard">Dashboard</a>')
        if session.get("role") == "admin":
            parts.append('<a href="/admin">Admin</a>')
        parts.append(f'<a href="/logout">Logout ({session["user"]})</a>')
    else:
        parts.append('<a href="/login">Login</a>')
    return " ".join(parts)


# ── Pages ────────────────────────────────────────────────────

@app.route("/")
def index():
    return (
        "<!doctype html>"
        "<title>Archivex — Document Archive</title>"
        f"{STYLE}"
        "<h1>Archivex</h1>"
        '<p class="sub">Company Document Archive</p>'
        f"<nav>{nav()}</nav>"
        '<div id="docs">Loading documents…</div>'
        "<script>"
        "fetch('/api/docs').then(r=>r.json()).then(data=>{"
        "const el=document.getElementById('docs');el.innerHTML='';"
        "data.docs.forEach(d=>{"
        "const c=document.createElement('div');c.className='card';"
        "c.innerHTML='<h3>'+d.title+'</h3><p>'+d.body.substring(0,160)+'…</p>';"
        "el.appendChild(c);});"
        "});"
        "</script>"
    )


@app.route("/login")
def login_page():
    return (
        "<!doctype html>"
        "<title>Archivex — Login</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Archivex Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/" style="color:#00cc66;text-decoration:none">'
        "← Back to archive</a></p></div>"
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
        "<title>Archivex — Dashboard</title>"
        f"{STYLE}"
        "<h1>Dashboard</h1>"
        f'<p class="sub">Signed in as {session["user"]} '
        f'({session.get("role", "")})</p>'
        f"<nav>{nav()}</nav>"
        '<div class="section">'
        "<h2>Import Records (XML)</h2>"
        '<textarea id="xml" spellcheck="false" placeholder='
        "'<records>&#10;  <record>&#10;    <title>Document Title</title>&#10;"
        "    <body>Content here</body>&#10;  </record>&#10;</records>'"
        "></textarea>"
        '<button onclick="doImport()">Import</button>'
        '<p class="muted">Upload XML records. See the Data Import Service '
        "guide for format details.</p>"
        '<div id="out" class="result"></div></div>'
        "<script>"
        "async function doImport(){"
        "const r=await fetch('/api/import',{method:'POST',"
        "headers:{'Content-Type':'application/xml'},"
        "body:document.getElementById('xml').value});"
        "const d=await r.json(),el=document.getElementById('out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#00cc66';"
        "el.textContent='Imported '+d.count+' record(s): '"
        "+JSON.stringify(d.records);}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/admin")
def admin_page():
    if session.get("role") != "admin":
        return redirect("/login")
    return (
        "<!doctype html>"
        "<title>Archivex — Admin</title>"
        f"{STYLE}"
        "<h1>Admin Panel</h1>"
        '<p class="sub">Administration tools</p>'
        f"<nav>{nav()}</nav>"
        '<div class="section">'
        "<h2>Metric Calculator</h2>"
        '<p class="muted">Evaluate expressions for ad-hoc metric '
        "calculations.</p>"
        "<label>Expression</label>"
        '<input id="expr" type="text" placeholder="sum([100, 200, 300])" '
        'style="max-width:100%">'
        '<button onclick="doCalc()">Calculate</button>'
        '<div id="out" class="result"></div></div>'
        "<script>"
        "async function doCalc(){"
        "const r=await fetch('/api/calc',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({expression:document.getElementById('expr').value})});"
        "const d=await r.json(),el=document.getElementById('out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#00cc66';el.textContent='Result: '+d.result;}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── API ──────────────────────────────────────────────────────

@app.route("/api/docs")
def api_docs_list():
    conn = get_db()
    public = conn.execute(
        "SELECT id, title, body FROM docs WHERE restricted=0 ORDER BY id"
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) c FROM docs").fetchone()["c"]
    conn.close()
    return jsonify(
        docs=[{"id": d["id"], "title": d["title"], "body": d["body"],
               "restricted": False} for d in public],
        total=total, showing=len(public),
    )


@app.route("/api/docs/<int:doc_id>")
def api_doc_detail(doc_id):
    conn = get_db()
    doc = conn.execute("SELECT * FROM docs WHERE id=?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        return jsonify(ok=False, error="not found"), 404
    return jsonify(ok=True, id=doc["id"], title=doc["title"],
                   body=doc["body"], restricted=bool(doc["restricted"]))


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", ""), data.get("password", "")
    conn = get_db()
    row = conn.execute(
        "SELECT username, role FROM users WHERE username=? AND password=?",
        (u, p)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False, error="invalid credentials"), 401
    session["user"] = row["username"]
    session["role"] = row["role"]
    return jsonify(ok=True, user=row["username"], role=row["role"])


@app.route("/api/import", methods=["POST"])
def api_import():
    if "user" not in session:
        return jsonify(ok=False, error="authentication required"), 401

    raw = request.get_data()
    if not raw:
        return jsonify(ok=False, error="empty body"), 400
    try:
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        root = etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError as e:
        return jsonify(ok=False, error=f"XML parse error: {e}"), 400

    records = []
    conn = get_db()
    for rec in root.findall("record"):
        title = (rec.findtext("title") or "").strip()
        body = (rec.findtext("body") or "").strip()
        if title or body:
            conn.execute("INSERT INTO records VALUES (NULL,?,?)", (title, body))
            records.append({"title": title, "body": body})
    conn.commit()
    conn.close()

    if not records:
        return jsonify(ok=False, error="no <record> elements found"), 400
    return jsonify(ok=True, count=len(records), records=records)


CALC_BLOCKED = ["import", "os", "system", "subprocess", "exec",
                "compile", "eval", "__builtins__", "globals", "locals"]


@app.route("/api/calc", methods=["POST"])
def api_calc():
    if session.get("role") != "admin":
        return jsonify(ok=False, error="admin access required"), 403
    data = request.get_json(silent=True) or {}
    expr = data.get("expression", "").strip()
    if not expr:
        return jsonify(ok=False, error="expression required"), 400
    for word in CALC_BLOCKED:
        if word in expr.lower():
            return jsonify(ok=False, error=f"blocked keyword: {word}"), 400
    try:
        result = eval(expr)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400
    return jsonify(ok=True, result=str(result))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
