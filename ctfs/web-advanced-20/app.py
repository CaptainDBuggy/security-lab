"""
Patchwork — Advanced Web CTF  (challenge 20)

Three-flag chain, higher difficulty:
JWT weak secret  →  SSTI (Jinja2)  →  Path traversal with filter bypass

1. Authentication uses JWTs signed with HS256. The signing secret is a
   common dictionary word ("secret"). Crack it, forge a token with
   role "admin", access /admin for flag1.                                   (flag1)

2. Admin panel has a template preview feature that renders user input
   through Jinja2 without sandboxing. A keyword filter blocks shell
   execution but not file reads. Use Jinja2 object traversal to read
   /flag2.txt.                                                              (flag2)

3. A snippet download endpoint takes a filename parameter and strips
   "../" from the path — but only once. Use "....//....//flag3.txt"
   to bypass the filter and read /flag3.txt.                                (flag3)

Fixes:
 - JWT: use a strong random secret (>=32 bytes), not a dictionary word.
 - Template: never render user input through a template engine. Use
   autoescape and a logic-less template language for user content.
 - Download: resolve the canonical path with os.path.realpath() and
   verify the result starts with the allowed directory prefix.
"""

from flask import Flask, request, jsonify, make_response, redirect
from jinja2 import Environment
import jwt, secrets, os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

JWT_SECRET = "secret"
FLAG1 = "FLAG{jwt_w34k_s3cr3t_cr4ck3d}"
USERS = {"guest": "guest"}

os.makedirs("/app/snippets", exist_ok=True)
with open("/flag2.txt", "w") as f:
    f.write("FLAG{sst1_j1nj4_0bj3ct_tr4v3rs4l}")
with open("/flag3.txt", "w") as f:
    f.write("FLAG{p4th_tr4v3rs4l_f1lt3r_byp4ss}")
with open("/app/snippets/hello.py", "w") as f:
    f.write("print('Hello, world!')\n")
with open("/app/snippets/fibonacci.py", "w") as f:
    f.write("def fib(n):\n    a, b = 0, 1\n"
            "    for _ in range(n):\n        a, b = b, a+b\n    return a\n")
with open("/app/snippets/sort.py", "w") as f:
    f.write("def quicksort(arr):\n    if len(arr) <= 1: return arr\n"
            "    pivot = arr[0]\n"
            "    return quicksort([x for x in arr[1:] if x < pivot])"
            " + [pivot] + quicksort([x for x in arr[1:] if x >= pivot])\n")


TEMPLATE_BLOCKED = ["import", "os.", "system", "subprocess", "popen",
                    "eval(", "exec(", "breakpoint"]


def decode_token():
    raw = request.cookies.get("token")
    if not raw:
        return None
    try:
        return jwt.decode(raw, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


# ── Shared HTML ─────────────────────────────────────────────────

STYLE = (
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#0a0a0a;"
    "color:#c8c8c8;padding:2rem}"
    "h1{color:#cc6633;margin-bottom:.3rem}"
    ".sub{color:#555;margin-bottom:1.5rem}"
    "nav{margin-bottom:2rem}"
    "nav a{color:#cc6633;text-decoration:none;margin-right:1.5rem}"
    "nav a:hover{text-decoration:underline}"
    ".card{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.2rem;margin:.8rem 0}"
    ".card h3{color:#cc6633;font-size:.95rem;margin-bottom:.4rem}"
    ".card p{color:#888;font-size:.85rem;line-height:1.4}"
    "textarea{width:100%;height:140px;background:#080808;color:#c8c8c8;"
    "border:1px solid #333;border-radius:4px;padding:.8rem;"
    "font-family:monospace;font-size:.85rem;resize:vertical}"
    "input[type=text],input[type=password]{width:100%;max-width:360px;"
    "padding:.55rem;background:#080808;color:#c8c8c8;border:1px solid #333;"
    "border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}"
    "label{display:block;color:#666;font-size:.8rem;text-transform:uppercase;"
    "margin-bottom:.2rem;letter-spacing:.04em}"
    "button{background:#cc6633;color:#000;border:none;padding:.55rem 1.4rem;"
    "border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;"
    "margin-top:.3rem}"
    "button:hover{background:#dd7744}"
    ".result{margin-top:1rem;padding:1rem;background:#080808;"
    "border:1px solid #333;border-radius:4px;white-space:pre-wrap;"
    "font-size:.85rem;display:none}"
    ".muted{color:#444;font-size:.8rem;margin-top:.4rem}"
    ".section{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.5rem;margin:1.5rem 0}"
    ".section h2{color:#cc6633;font-size:1rem;margin-bottom:.8rem}"
    "#msg{margin-top:.8rem;color:#cc3333;font-size:.9rem}"
    ".badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;"
    "font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}"
    ".badge-role{background:#331a0a;color:#cc6633;border:1px solid #804020}"
    "</style>"
)


def nav(tok):
    parts = ['<a href="/">Snippets</a>']
    if tok:
        parts.append('<a href="/dashboard">Dashboard</a>')
        if tok.get("role") == "admin":
            parts.append('<a href="/admin">Admin</a>')
        parts.append(f'<a href="/logout">Logout ({tok.get("user", "")})</a>')
    else:
        parts.append('<a href="/login">Login</a>')
    return " ".join(parts)


# ── Pages ───────────────────────────────────────────────────────

@app.route("/")
def index():
    tok = decode_token()
    return (
        "<!doctype html>"
        "<title>Patchwork — Snippet Sharing</title>"
        f"{STYLE}"
        "<h1>Patchwork</h1>"
        '<p class="sub">Code Snippet Sharing</p>'
        f"<nav>{nav(tok)}</nav>"
        '<div class="card"><h3>hello.py</h3>'
        "<p>A simple hello world program. Shared by admin.</p></div>"
        '<div class="card"><h3>fibonacci.py</h3>'
        "<p>Classic Fibonacci sequence generator. Shared by admin.</p></div>"
        '<div class="card"><h3>sort.py</h3>'
        "<p>Quicksort implementation in Python. Shared by admin.</p></div>"
    )


@app.route("/login")
def login_page():
    return (
        "<!doctype html>"
        "<title>Patchwork — Login</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Patchwork Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p class="muted" style="text-align:center;margin-top:1rem">'
        "Demo account: guest / guest</p>"
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/" style="color:#cc6633;text-decoration:none">'
        "← Back to snippets</a></p></div>"
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
    tok = decode_token()
    if not tok:
        return redirect("/login")
    return (
        "<!doctype html>"
        "<title>Patchwork — Dashboard</title>"
        f"{STYLE}"
        "<h1>Dashboard</h1>"
        f'<p class="sub">{tok.get("user", "")} '
        f'<span class="badge badge-role">{tok.get("role", "")}</span></p>'
        f"<nav>{nav(tok)}</nav>"
        '<div class="section">'
        "<h2>Your Snippets</h2>"
        '<div class="card"><h3>notes.txt</h3>'
        "<p>Personal notes — last edited yesterday</p></div>"
        "</div>"
        '<div class="section">'
        "<h2>Access Level</h2>"
        f'<p>Role: <strong>{tok.get("role", "viewer")}</strong></p>'
        '<p class="muted">Viewers can read public snippets. '
        "Admin access is required for template management, "
        "file operations, and user administration.</p>"
        "</div>"
    )


@app.route("/admin")
def admin_page():
    tok = decode_token()
    if not tok or tok.get("role") != "admin":
        return jsonify(ok=False, error="admin role required"), 403
    return (
        "<!doctype html>"
        "<title>Patchwork — Admin</title>"
        f"{STYLE}"
        "<h1>Admin Panel</h1>"
        '<p class="sub">System administration</p>'
        f"<nav>{nav(tok)}</nav>"
        '<div class="section">'
        "<h2>Admin Access Verified</h2>"
        f'<p style="color:#33cc66;font-size:1.1rem;margin-bottom:.5rem">'
        f"{FLAG1}</p>"
        '<p class="muted">Token integrity note: HS256 security depends '
        "entirely on secret strength.</p></div>"
        '<div class="section">'
        "<h2>Template Preview</h2>"
        '<p class="muted">Preview notification templates. Supports '
        "Jinja2 syntax for dynamic content.</p>"
        '<textarea id="tpl" spellcheck="false" '
        'placeholder="Hello {{ user }}, welcome to Patchwork!"></textarea>'
        '<button onclick="doPreview()">Render Preview</button>'
        '<div id="tpl-out" class="result"></div></div>'
        '<div class="section">'
        "<h2>Snippet Files</h2>"
        '<p class="muted">Download raw snippet files from the archive.</p>'
        '<div class="card"><h3>hello.py</h3>'
        '<p><a href="/api/snippets/download?file=hello.py" '
        'style="color:#cc6633">Download</a></p></div>'
        '<div class="card"><h3>fibonacci.py</h3>'
        '<p><a href="/api/snippets/download?file=fibonacci.py" '
        'style="color:#cc6633">Download</a></p></div>'
        '<div class="card"><h3>sort.py</h3>'
        '<p><a href="/api/snippets/download?file=sort.py" '
        'style="color:#cc6633">Download</a></p></div></div>'
        "<script>"
        "async function doPreview(){"
        "const r=await fetch('/api/template/preview',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({template:document.getElementById('tpl').value})});"
        "const d=await r.json(),el=document.getElementById('tpl-out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#33cc66';el.textContent=d.rendered;}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("token")
    return resp


# ── API ─────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", ""), data.get("password", "")
    if USERS.get(u) != p:
        return jsonify(ok=False, error="invalid credentials"), 401
    token = jwt.encode({"user": u, "role": "viewer"}, JWT_SECRET,
                       algorithm="HS256")
    resp = make_response(jsonify(ok=True, user=u, role="viewer"))
    resp.set_cookie("token", token)
    return resp


@app.route("/api/template/preview", methods=["POST"])
def api_template_preview():
    tok = decode_token()
    if not tok or tok.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    data = request.get_json(silent=True) or {}
    tpl = data.get("template", "").strip()
    if not tpl:
        return jsonify(ok=False, error="template required"), 400
    for word in TEMPLATE_BLOCKED:
        if word in tpl.lower():
            return jsonify(ok=False, error=f"blocked keyword: {word}"), 400
    try:
        env = Environment()
        rendered = env.from_string(tpl).render(
            user="demo-user", app_name="Patchwork")
        return jsonify(ok=True, rendered=rendered)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400


SNIPPETS_DIR = "/app/snippets"


@app.route("/api/snippets/download")
def api_download():
    tok = decode_token()
    if not tok or tok.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    fname = request.args.get("file", "")
    if not fname:
        return jsonify(ok=False, error="file parameter required"), 400
    sanitized = fname.replace("../", "")
    path = os.path.join(SNIPPETS_DIR, sanitized)
    try:
        with open(path, "r") as f:
            content = f.read()
        return jsonify(ok=True, filename=fname, content=content)
    except FileNotFoundError:
        return jsonify(ok=False, error="file not found"), 404
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
