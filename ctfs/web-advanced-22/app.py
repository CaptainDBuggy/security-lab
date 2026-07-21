#!/usr/bin/env python3
"""Dataroom — Secure File Vault (CTF 22)

Chain: JWT Algorithm Confusion → NoSQL Operator Injection → YAML Deserialization RCE
"""

import os, json, re, sqlite3, hashlib, secrets, base64
import hmac as _hmac
from datetime import datetime, timedelta, timezone
from functools import wraps

import yaml
import jwt
from flask import Flask, request, jsonify, g, make_response

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

FLAG1 = "FLAG{jwt_4lg0r1thm_c0nfus10n}"
FLAG2 = "FLAG{n0sql_0p3r4t0r_1nj3ct10n}"
FLAG3 = "FLAG{y4ml_d3s3r14l1z4t10n_rc3}"

# ── RSA key pair (generated fresh each container start) ──

_rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

PRIVATE_PEM = _rsa_private.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
PUBLIC_PEM = _rsa_private.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

# ── SQLite ──

DB = "/tmp/dataroom.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'viewer'
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            classification TEXT DEFAULT 'public',
            content TEXT,
            owner TEXT,
            created_at TEXT
        );
    """)

    pw = hashlib.sha256("d4t4r00m_v4ult_m4st3r".encode()).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)",
        ("admin", pw, "admin"),
    )

    seed_docs = [
        ("Q3 Revenue Report", "public",
         "Revenue reached $4.2M, up 18% YoY. Expansion on track.", "admin"),
        ("Team Standup Notes", "public",
         "Sprint 14 retro: deployment pipeline needs hardening.", "admin"),
        ("API Integration Guide", "internal",
         "Bearer JWT (RS256) on all /api/v2 endpoints. Rate limit 100/min.", "admin"),
        ("Infrastructure Diagram", "internal",
         "Primary DB: PostgreSQL on db-prod-01. Redis cache on cache-01.", "admin"),
        ("Acquisition Target Analysis", "classified",
         f"Target valuation: $45M. Board approval pending.\n\n{FLAG2}", "admin"),
        ("Incident Response Playbook", "classified",
         "On breach: isolate affected hosts, notify CISO within 1 hr.", "admin"),
        ("Encryption Key Rotation Log", "restricted",
         "Last rotation: 2026-06-15. Next: 2026-09-15. AES-256-GCM.", "admin"),
    ]
    for title, cls, content, owner in seed_docs:
        db.execute(
            "INSERT OR IGNORE INTO documents "
            "(title, classification, content, owner, created_at) VALUES (?,?,?,?,?)",
            (title, cls, content, owner, datetime.now(timezone.utc).isoformat()),
        )

    db.commit()
    db.close()

    with open("/tmp/vault_master_key.txt", "w") as f:
        f.write(
            f"{FLAG3}\n\n"
            "Vault Master Encryption Key\n"
            "Algorithm : AES-256-GCM\n"
            "Key       : 4f9a2c8d1e7b3f6a0d5c8e2b7a1f4d9c\n"
            "Rotation  : quarterly\n"
        )


# ── JWT helpers ──


def create_token(user_id, username, role):
    payload = {
        "sub": user_id,
        "user": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, PRIVATE_PEM, algorithm="RS256")


def _b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def verify_token(token):
    """VULNERABLE: trusts the alg header from the token itself."""
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "RS256")

        if alg in ("HS256", "HS384", "HS512"):
            hash_fn = {"HS256": hashlib.sha256,
                       "HS384": hashlib.sha384,
                       "HS512": hashlib.sha512}[alg]
            parts = token.split(".")
            if len(parts) != 3:
                return None
            sig = _b64url_decode(parts[2])
            expected = _hmac.new(
                PUBLIC_PEM, f"{parts[0]}.{parts[1]}".encode(), hash_fn
            ).digest()
            if not _hmac.compare_digest(sig, expected):
                return None
            payload_json = _b64url_decode(parts[1])
            claims = json.loads(payload_json)
            if claims.get("exp", 0) < datetime.now(timezone.utc).timestamp():
                return None
            return claims
        else:
            return jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"])
    except Exception:
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("token") or \
                request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return jsonify({"ok": False, "error": "authentication required"}), 401
        claims = verify_token(token)
        if not claims:
            return jsonify({"ok": False, "error": "invalid or expired token"}), 401
        g.user = claims
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if g.user.get("role") != "admin":
            return jsonify({"ok": False, "error": "admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper


# ── NoSQL-style query engine ──


def match_value(doc_val, query_val):
    if isinstance(query_val, dict):
        for op, operand in query_val.items():
            if op == "$eq" and doc_val != operand:
                return False
            elif op == "$ne" and doc_val == operand:
                return False
            elif op == "$gt" and not (doc_val > operand):
                return False
            elif op == "$lt" and not (doc_val < operand):
                return False
            elif op == "$gte" and not (doc_val >= operand):
                return False
            elif op == "$lte" and not (doc_val <= operand):
                return False
            elif op == "$regex" and not re.search(operand, str(doc_val), re.IGNORECASE):
                return False
            elif op == "$in" and doc_val not in operand:
                return False
            elif op == "$exists":
                if operand and doc_val is None:
                    return False
                if not operand and doc_val is not None:
                    return False
        return True
    return doc_val == query_val


def query_documents(docs, query):
    results = []
    for doc in docs:
        if all(match_value(doc.get(k), v) for k, v in query.items()):
            results.append(doc)
    return results


# ── Shared CSS ──

CSS = (
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#080810;color:#c0c4d0;"
    "padding:2rem}"
    "h1{color:#4488ee;margin-bottom:.3rem}"
    ".sub{color:#555;margin-bottom:1.5rem}"
    "nav{margin-bottom:2rem}"
    "nav a{color:#4488ee;text-decoration:none;margin-right:1.5rem}"
    "nav a:hover{text-decoration:underline}"
    ".card{background:#0e1018;border:1px solid #1a1e2a;border-radius:6px;"
    "padding:1.2rem;margin:.8rem 0}"
    ".card h3{color:#4488ee;font-size:.95rem;margin-bottom:.4rem}"
    ".card p{color:#888;font-size:.85rem;line-height:1.4}"
    "textarea{width:100%;height:160px;background:#060610;color:#c0c4d0;"
    "border:1px solid #252a38;border-radius:4px;padding:.8rem;"
    "font-family:monospace;font-size:.85rem;resize:vertical}"
    "input[type=text],input[type=password]{width:100%;max-width:360px;"
    "padding:.55rem;background:#060610;color:#c0c4d0;border:1px solid #252a38;"
    "border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}"
    "label{display:block;color:#556;font-size:.8rem;text-transform:uppercase;"
    "margin-bottom:.2rem;letter-spacing:.04em}"
    "button{background:#4488ee;color:#fff;border:none;padding:.55rem 1.4rem;"
    "border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;"
    "margin-top:.3rem}"
    "button:hover{background:#5599ff}"
    ".result{margin-top:1rem;padding:1rem;background:#060610;"
    "border:1px solid #252a38;border-radius:4px;white-space:pre-wrap;"
    "font-size:.85rem;display:none}"
    ".muted{color:#445;font-size:.8rem;margin-top:.4rem}"
    ".section{background:#0e1018;border:1px solid #1a1e2a;border-radius:6px;"
    "padding:1.5rem;margin:1.5rem 0}"
    ".section h2{color:#4488ee;font-size:1rem;margin-bottom:.8rem}"
    "#msg{margin-top:.8rem;color:#ee4444;font-size:.9rem}"
    ".badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;"
    "font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}"
    ".badge-role{background:#102040;color:#4488ee;border:1px solid #204080}"
    ".badge-pub{background:#0a2818;color:#33cc66;border:1px solid #196b3a}"
    ".badge-int{background:#2a2810;color:#ccaa33;border:1px solid #8a7520}"
    ".badge-cls{background:#2a1018;color:#ee4466;border:1px solid #802040}"
    ".badge-rst{background:#1a1028;color:#aa66ee;border:1px solid #6030a0}"
    ".doc-row{display:flex;justify-content:space-between;align-items:center;"
    "padding:.6rem 0;border-bottom:1px solid #1a1e2a}"
    ".doc-row:last-child{border-bottom:none}"
    ".doc-info{color:#888;font-size:.85rem}"
    ".doc-info strong{color:#c0c4d0}"
    ".btn-sm{background:#1a1e2a;color:#4488ee;border:1px solid #252a38;"
    "padding:.3rem .8rem;border-radius:3px;cursor:pointer;"
    "font-family:monospace;font-size:.8rem}"
    ".btn-sm:hover{background:#252a38}"
)

BADGE_MAP = {
    "public": "badge-pub",
    "internal": "badge-int",
    "classified": "badge-cls",
    "restricted": "badge-rst",
}


# ── Page routes ──


@app.route("/")
def index():
    db = get_db()
    docs = db.execute(
        "SELECT title, classification FROM documents WHERE classification='public'"
    ).fetchall()
    cards = "".join(
        f'<div class="card"><h3>{d["title"]}</h3>'
        f'<p><span class="badge {BADGE_MAP.get(d["classification"], "")}">'
        f'{d["classification"]}</span></p></div>'
        for d in docs
    )
    return (
        f'<!doctype html><title>Dataroom</title><style>{CSS}</style>'
        f'<h1>Dataroom</h1><p class="sub">Secure Document Sharing</p>'
        f'<nav><a href="/">Documents</a> <a href="/login">Login</a> '
        f'<a href="/register">Register</a></nav>'
        f'<div class="section"><h2>Public Documents</h2>{cards}'
        f'<p class="muted" style="margin-top:1rem">'
        f"Login to access internal documents. "
        f"Classified materials require admin clearance.</p></div>"
        f'<!-- dataroom-api v2.1 | auth: RS256 JWT | see /api -->'
    )


@app.route("/login")
def login_page():
    return (
        f'<!doctype html><title>Dataroom — Login</title><style>{CSS}</style>'
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Dataroom Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/register" style="color:#4488ee;text-decoration:none">'
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


@app.route("/register")
def register_page():
    return (
        f'<!doctype html><title>Dataroom — Register</title><style>{CSS}</style>'
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Create Account</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doReg()" style="width:100%">Register</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/login" style="color:#4488ee;text-decoration:none">'
        "Already have an account? Login</a></p></div>"
        "<script>"
        "async function doReg(){"
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


@app.route("/dashboard")
@require_auth
def dashboard():
    u = g.user
    is_admin = u.get("role") == "admin"
    admin_link = ' <a href="/admin">Vault Admin</a>' if is_admin else ""
    return (
        f'<!doctype html><title>Dataroom — Dashboard</title><style>{CSS}</style>'
        f'<h1>Dashboard</h1><p class="sub">{u["user"]} '
        f'<span class="badge badge-role">{u["role"]}</span></p>'
        f'<nav><a href="/">Documents</a> <a href="/dashboard">Dashboard</a>'
        f'{admin_link} <a href="/logout">Logout</a></nav>'
        f'<div class="section"><h2>Your Access</h2>'
        f'<p>Role: <strong>{u["role"]}</strong></p>'
        f'<p class="muted">Viewers can access public documents. '
        f"Admin clearance required for classified materials and vault "
        f"management.</p></div>"
        f'<div class="section"><h2>Document Search</h2>'
        f'<p class="muted">Search documents by classification. '
        f"Viewers can only access public documents.</p>"
        f'<label>Classification</label>'
        f'<input id="cls" type="text" placeholder="public" '
        f'style="max-width:200px">'
        f'<button onclick="doSearch()">Search</button>'
        f'<div id="search-out" class="result"></div></div>'
        "<script>"
        "async function doSearch(){"
        "const c=document.getElementById('cls').value;"
        "const r=await fetch('/api/documents?classification='+encodeURIComponent(c));"
        "const d=await r.json(),el=document.getElementById('search-out');"
        "el.style.display='block';"
        "if(d.ok){"
        "el.style.color='#33cc66';"
        "let t='Found '+d.documents.length+' document(s):\\n\\n';"
        "d.documents.forEach(x=>{"
        "t+='  ['+x.classification.toUpperCase()+'] '+x.title+'\\n';"
        "if(x.content)t+='  '+x.content.substring(0,200)+'\\n\\n';});"
        "el.textContent=t;}else{"
        "el.style.color='#ee4444';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/admin")
@require_admin
def admin_page():
    return (
        f'<!doctype html><title>Dataroom — Vault Admin</title><style>{CSS}</style>'
        f'<h1>Vault Admin</h1><p class="sub">Administrative controls</p>'
        f'<nav><a href="/">Documents</a> <a href="/dashboard">Dashboard</a> '
        f'<a href="/admin">Vault Admin</a> <a href="/logout">Logout</a></nav>'
        f'<div class="section"><h2>Admin Access Granted</h2>'
        f'<p style="color:#33cc66;font-size:1.1rem;margin-bottom:.5rem">{FLAG1}</p>'
        f'<p class="muted">JWT verification accepted an unexpected algorithm.</p></div>'
        f'<div class="section"><h2>Advanced Document Query</h2>'
        f'<p class="muted">Query the document vault using JSON filter syntax. '
        f"Supports operators: <code>$eq</code>, <code>$ne</code>, "
        f"<code>$gt</code>, <code>$lt</code>, <code>$regex</code>, "
        f"<code>$in</code>.</p>"
        f'<textarea id="query" spellcheck="false" '
        f'placeholder=\'{{"classification": "internal"}}\'></textarea>'
        f'<button onclick="doQuery()">Execute Query</button>'
        f'<div id="query-out" class="result"></div></div>'
        f'<div class="section"><h2>Import Document Metadata</h2>'
        f'<p class="muted">Import document metadata from YAML configuration.</p>'
        f'<textarea id="yml" spellcheck="false" '
        f"placeholder=\"title: New Document&#10;"
        f"classification: internal&#10;"
        f'content: Document body here"></textarea>'
        f'<button onclick="doImport()">Import YAML</button>'
        f'<div id="import-out" class="result"></div></div>'
        "<script>"
        "async function doQuery(){"
        "const r=await fetch('/api/admin/query',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:document.getElementById('query').value});"
        "const d=await r.json(),el=document.getElementById('query-out');"
        "el.style.display='block';"
        "if(d.ok){"
        "el.style.color='#33cc66';"
        "let t='Results: '+d.results.length+' document(s)\\n\\n';"
        "d.results.forEach(x=>{"
        "t+='  ['+x.classification.toUpperCase()+'] '+x.title+'\\n';"
        "t+='  '+(x.content||'(no content)')+'\\n\\n';});"
        "el.textContent=t;}else{"
        "el.style.color='#ee4444';el.textContent='Error: '+d.error;}}"
        "async function doImport(){"
        "const r=await fetch('/api/admin/import-yaml',{method:'POST',"
        "headers:{'Content-Type':'application/x-yaml'},"
        "body:document.getElementById('yml').value});"
        "const d=await r.json(),el=document.getElementById('import-out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#33cc66';"
        "el.textContent='Imported: '+JSON.stringify(d.imported);}"
        "else{el.style.color='#ee4444';"
        "el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/logout")
def logout():
    resp = make_response(
        f'<!doctype html><title>Dataroom — Logout</title><style>{CSS}</style>'
        '<div style="max-width:380px;margin:4rem auto;text-align:center">'
        "<h1>Logged Out</h1>"
        '<p class="muted" style="margin:1rem 0">'
        '<a href="/login" style="color:#4488ee">Return to login</a></p></div>'
    )
    resp.delete_cookie("token")
    return resp


# ── API routes ──


@app.route("/api")
def api_info():
    return jsonify({
        "name": "Dataroom API",
        "version": "2.1.0",
        "auth": {
            "type": "JWT",
            "algorithm": "RS256",
            "public_key": "/api/public-key",
        },
        "endpoints": {
            "login": "POST /api/login",
            "register": "POST /api/register",
            "documents": "GET /api/documents?classification=<level>",
        },
    })


@app.route("/api/public-key")
def api_public_key():
    return PUBLIC_PEM.decode(), 200, {"Content-Type": "text/plain"}


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"})
    if len(username) < 2 or len(username) > 30:
        return jsonify({"ok": False, "error": "username must be 2-30 characters"})

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return jsonify({"ok": False, "error": "username taken"})

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        (username, pw_hash, "viewer"),
    )
    db.commit()
    return jsonify({"ok": True, "user": username})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    db = get_db()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    user = db.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, pw_hash),
    ).fetchone()
    if not user:
        return jsonify({"ok": False, "error": "invalid credentials"})

    token = create_token(user["id"], user["username"], user["role"])
    resp = make_response(
        jsonify({"ok": True, "user": user["username"], "role": user["role"]})
    )
    resp.set_cookie("token", token, httponly=True)
    return resp


@app.route("/api/documents")
@require_auth
def api_documents():
    classification = request.args.get("classification", "public")
    u = g.user

    if u.get("role") != "admin" and classification != "public":
        return jsonify({
            "ok": False,
            "error": f"insufficient clearance for {classification} documents",
        })

    db = get_db()
    docs = db.execute(
        "SELECT id,title,classification,content FROM documents "
        "WHERE classification=?",
        (classification,),
    ).fetchall()

    return jsonify({
        "ok": True,
        "documents": [
            {
                "id": d["id"],
                "title": d["title"],
                "classification": d["classification"],
                "content": d["content"]
                if u.get("role") == "admin"
                else (d["content"] or "")[:80] + "...",
            }
            for d in docs
        ],
    })


@app.route("/api/admin/query", methods=["POST"])
@require_admin
def api_admin_query():
    try:
        query = request.get_json(force=True)
        if not isinstance(query, dict):
            return jsonify({"ok": False, "error": "query must be a JSON object"})
    except Exception:
        return jsonify({"ok": False, "error": "invalid JSON"})

    # Security: classified documents require vault supervisor clearance
    if query.get("classification") == "classified":
        return jsonify({
            "ok": False,
            "error": "classified documents require vault supervisor clearance",
        })

    db = get_db()
    rows = db.execute(
        "SELECT id,title,classification,content,owner FROM documents"
    ).fetchall()
    docs = [
        {
            "id": r["id"],
            "title": r["title"],
            "classification": r["classification"],
            "content": r["content"],
            "owner": r["owner"],
        }
        for r in rows
    ]

    results = query_documents(docs, query)

    return jsonify({
        "ok": True,
        "results": [
            {"title": d["title"], "classification": d["classification"],
             "content": d["content"]}
            for d in results
        ],
    })


@app.route("/api/admin/import-yaml", methods=["POST"])
@require_admin
def api_import_yaml():
    raw = request.get_data(as_text=True)
    if not raw.strip():
        return jsonify({"ok": False, "error": "empty YAML body"})

    try:
        data = yaml.unsafe_load(raw)

        if isinstance(data, dict):
            title = data.get("title", "Untitled")
            classification = data.get("classification", "internal")
            content = data.get("content", "")
            db = get_db()
            db.execute(
                "INSERT INTO documents "
                "(title,classification,content,owner,created_at) VALUES (?,?,?,?,?)",
                (str(title), str(classification), str(content), g.user["user"],
                 datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
            return jsonify({
                "ok": True,
                "imported": {"title": str(title),
                             "classification": str(classification)},
            })
        else:
            return jsonify({"ok": True, "imported": str(data)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Boot ──

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
