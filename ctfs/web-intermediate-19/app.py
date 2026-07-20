"""
Vaultline — Intermediate Web CTF  (challenge 19)

Three-flag chain using three distinct vulnerability classes:
Cookie tampering  →  SSRF (internal service)  →  SSRF (file:// protocol)

1. Session cookie is base64-encoded JSON with no signature. Decode it,
   change role from "viewer" to "admin", re-encode. GET /admin shows
   flag1 and the webhook testing feature.                                   (flag1)

2. Admin panel JS fetches /api/status, whose response lists an internal
   metadata service at http://localhost:9090. The webhook tester makes
   server-side requests — hit http://localhost:9090/metadata for flag2
   + a file path hint.                                                      (flag2)

3. The webhook fetcher does not restrict URL schemes. Use
   file:///flag3.txt to read the final flag from disk.                      (flag3)

Fixes:
 - Session: use cryptographically signed cookies (Flask's built-in
   session with a strong secret_key, or JWTs with signature verification).
 - Webhook: allowlist schemes (http/https only), block requests to
   private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
   169.254.0.0/16), use a URL validation library.
"""

from flask import Flask, request, jsonify, make_response, redirect
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading, base64, json, os, urllib.request

app = Flask(__name__)

FLAG1 = "FLAG{c00k13_t4mp3r_r0l3_3sc4l4t10n}"
FLAG2 = "FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}"
INTERNAL_PORT = 9090

os.makedirs("/app", exist_ok=True)
with open("/flag3.txt", "w") as f:
    f.write("FLAG{ssrf_f1l3_pr0t0c0l_r34d}")


# ── Internal metadata service (localhost:9090, not exposed) ─────

class MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metadata":
            body = json.dumps({
                "service": "vaultline-metadata",
                "version": "1.0.2",
                "flag2": FLAG2,
                "note": "The webhook endpoint does not restrict URL schemes. "
                        "Sensitive configuration is stored at /flag3.txt.",
            })
        else:
            body = json.dumps({
                "service": "vaultline-metadata",
                "version": "1.0.2",
                "endpoints": ["/metadata"],
            })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


def _start_metadata():
    HTTPServer(("127.0.0.1", INTERNAL_PORT), MetadataHandler).serve_forever()


threading.Thread(target=_start_metadata, daemon=True).start()


# ── Cookie helpers ──────────────────────────────────────────────

USERS = {"guest": "guest"}


def encode_session(data):
    return base64.b64encode(json.dumps(data).encode()).decode()


def decode_session():
    raw = request.cookies.get("session_data")
    if not raw:
        return None
    try:
        return json.loads(base64.b64decode(raw).decode())
    except Exception:
        return None


# ── Shared HTML ─────────────────────────────────────────────────

STYLE = (
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:'Courier New',monospace;background:#0a0a0a;"
    "color:#c8c8c8;padding:2rem}"
    "h1{color:#3399ff;margin-bottom:.3rem}"
    ".sub{color:#555;margin-bottom:1.5rem}"
    "nav{margin-bottom:2rem}"
    "nav a{color:#3399ff;text-decoration:none;margin-right:1.5rem}"
    "nav a:hover{text-decoration:underline}"
    ".card{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.2rem;margin:.8rem 0}"
    ".card h3{color:#3399ff;font-size:.95rem;margin-bottom:.4rem}"
    ".card p{color:#888;font-size:.85rem;line-height:1.4}"
    "input[type=text],input[type=password]{width:100%;max-width:360px;"
    "padding:.55rem;background:#080808;color:#c8c8c8;border:1px solid #333;"
    "border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}"
    "label{display:block;color:#666;font-size:.8rem;text-transform:uppercase;"
    "margin-bottom:.2rem;letter-spacing:.04em}"
    "button{background:#3399ff;color:#000;border:none;padding:.55rem 1.4rem;"
    "border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;"
    "margin-top:.3rem}"
    "button:hover{background:#55aaff}"
    ".result{margin-top:1rem;padding:1rem;background:#080808;"
    "border:1px solid #333;border-radius:4px;white-space:pre-wrap;"
    "font-size:.85rem;display:none}"
    ".muted{color:#444;font-size:.8rem;margin-top:.4rem}"
    ".section{background:#111;border:1px solid #222;border-radius:6px;"
    "padding:1.5rem;margin:1.5rem 0}"
    ".section h2{color:#3399ff;font-size:1rem;margin-bottom:.8rem}"
    "#msg{margin-top:.8rem;color:#cc3333;font-size:.9rem}"
    ".badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;"
    "font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}"
    ".badge-ok{background:#0a3320;color:#33cc66;border:1px solid #196b3a}"
    ".badge-role{background:#0a1a33;color:#3399ff;border:1px solid #1a4080}"
    "</style>"
)


def nav(sess):
    parts = ['<a href="/">Vault</a>']
    if sess:
        parts.append('<a href="/dashboard">Dashboard</a>')
        if sess.get("role") == "admin":
            parts.append('<a href="/admin">Admin</a>')
        parts.append(f'<a href="/logout">Logout ({sess.get("user", "")})</a>')
    else:
        parts.append('<a href="/login">Login</a>')
    return " ".join(parts)


# ── Pages ───────────────────────────────────────────────────────

@app.route("/")
def index():
    sess = decode_session()
    return (
        "<!doctype html>"
        "<title>Vaultline — Secrets Manager</title>"
        f"{STYLE}"
        "<h1>Vaultline</h1>"
        '<p class="sub">Team Secrets Manager</p>'
        f"<nav>{nav(sess)}</nav>"
        '<div class="card"><h3>Secure Credential Storage</h3>'
        "<p>Store, share, and rotate team credentials with audit logging "
        "and role-based access control.</p></div>"
        '<div class="card"><h3>Webhook Integrations</h3>'
        "<p>Get notified when secrets are accessed or rotated via "
        "configurable webhook endpoints.</p></div>"
        '<div class="card"><h3>API Access</h3>'
        "<p>Programmatic access to your vault via authenticated REST API "
        "endpoints.</p></div>"
    )


@app.route("/login")
def login_page():
    return (
        "<!doctype html>"
        "<title>Vaultline — Login</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Vaultline Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p class="muted" style="text-align:center;margin-top:1rem">'
        "Demo account: guest / guest</p>"
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/" style="color:#3399ff;text-decoration:none">'
        "← Back to vault</a></p></div>"
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
    sess = decode_session()
    if not sess:
        return redirect("/login")
    return (
        "<!doctype html>"
        "<title>Vaultline — Dashboard</title>"
        f"{STYLE}"
        "<h1>Dashboard</h1>"
        f'<p class="sub">{sess.get("user", "")} '
        f'<span class="badge badge-role">{sess.get("role", "")}</span></p>'
        f"<nav>{nav(sess)}</nav>"
        '<div class="section">'
        "<h2>Your Secrets</h2>"
        '<div class="card"><h3>AWS Staging Key</h3>'
        "<p>AKIA••••••••EXAMPLE — last rotated 3 days ago</p></div>"
        '<div class="card"><h3>Database (read-only)</h3>'
        "<p>db-viewer@prod-replica — expires in 12 days</p></div>"
        "</div>"
        '<div class="section">'
        "<h2>Access Level</h2>"
        f'<p>Role: <strong>{sess.get("role", "viewer")}</strong></p>'
        '<p class="muted">Viewers can read shared secrets. '
        "Admin access is required for webhook configuration, "
        "system status, and user management.</p>"
        "</div>"
    )


@app.route("/admin")
def admin_page():
    sess = decode_session()
    if not sess or sess.get("role") != "admin":
        return jsonify(ok=False, error="admin role required"), 403
    return (
        "<!doctype html>"
        "<title>Vaultline — Admin</title>"
        f"{STYLE}"
        "<h1>Admin Panel</h1>"
        '<p class="sub">System administration</p>'
        f"<nav>{nav(sess)}</nav>"
        '<div class="section">'
        "<h2>Admin Access Granted</h2>"
        f'<p style="color:#33cc66;font-size:1.1rem;margin-bottom:.5rem">'
        f"{FLAG1}</p>"
        '<p class="muted">Session integrity check: role-based access '
        "control should use server-side verification.</p></div>"
        '<div class="section">'
        "<h2>System Status</h2>"
        '<div id="svc-list">Loading services…</div></div>'
        '<div class="section">'
        "<h2>Test Webhook</h2>"
        '<p class="muted">Send a test request to a webhook URL to verify '
        "connectivity.</p>"
        '<label>Webhook URL</label>'
        '<input id="url" type="text" placeholder="http://example.com/hook" '
        'style="max-width:100%">'
        '<button onclick="doTest()">Send Test</button>'
        '<div id="out" class="result"></div></div>'
        "<script>"
        "fetch('/api/status').then(r=>r.json()).then(data=>{"
        "const el=document.getElementById('svc-list');el.innerHTML='';"
        "data.services.forEach(s=>{"
        "el.innerHTML+='<div class=\"card\"><h3>'+s.name+'</h3>"
        "<p>Status: <span class=\"badge badge-ok\">'+s.status+'</span></p>"
        "</div>';});});"
        "async function doTest(){"
        "const r=await fetch('/api/webhook/test',{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({url:document.getElementById('url').value})});"
        "const d=await r.json(),el=document.getElementById('out');"
        "el.style.display='block';"
        "if(d.ok){el.style.color='#33cc66';el.textContent=d.body;}"
        "else{el.style.color='#cc3333';el.textContent='Error: '+d.error;}}"
        "</script>"
    )


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session_data")
    return resp


# ── API ─────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", ""), data.get("password", "")
    if USERS.get(u) != p:
        return jsonify(ok=False, error="invalid credentials"), 401
    token = encode_session({"user": u, "role": "viewer"})
    resp = make_response(jsonify(ok=True, user=u, role="viewer"))
    resp.set_cookie("session_data", token)
    return resp


@app.route("/api/status")
def api_status():
    sess = decode_session()
    if not sess or sess.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    return jsonify(services=[
        {"name": "database", "status": "healthy", "endpoint": "internal"},
        {"name": "metadata-svc", "status": "healthy",
         "endpoint": f"http://localhost:{INTERNAL_PORT}"},
        {"name": "vault-core", "status": "healthy", "endpoint": "internal"},
    ])


@app.route("/api/webhook/test", methods=["POST"])
def api_webhook_test():
    sess = decode_session()
    if not sess or sess.get("role") != "admin":
        return jsonify(ok=False, error="admin required"), 403
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify(ok=False, error="url required"), 400
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Vaultline/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
        return jsonify(ok=True, status=resp.status, body=body)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
