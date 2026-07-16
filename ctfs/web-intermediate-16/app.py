"""
Cogwheel CI — intermediate web CTF (a CHAINED box).

An internal continuous-integration / build-artifact server. Four deliberately-planted
weaknesses wired end-to-end: each stage hands you exactly what the next one needs, so
there is no path to flag 4 that skips 1 -> 2 -> 3. This is an attack *path*, not four
isolated puzzles.

  1. JWT forgery (alg:none)   -> your guest session is a signed JWT in the `cog_session`
     (auth bypass / BAC)         cookie. The verifier trusts a token whose header says
                                 {"alg":"none"} and skips the signature check entirely.
                                 Re-sign nothing: set alg=none, flip "role":"admin",
                                 drop the signature.  (flag1, on /admin)

  2. Server-Side Template     -> the admin "build announcement" preview renders your
     Injection (Jinja2)          input with render_template_string(). `{{7*7}}` proves it;
                                 `{{ config.items()|list }}` dumps the app config, which
                                 holds flag2 AND the unguessable name of the encrypted
                                 artifact bundle.  (flag2)

  3. Known-plaintext ZIP      -> /download hands you that ZipCrypto-encrypted bundle. You
     attack (bkcrack)            were never given its password — but one file inside it
                                 (banner.png) is also served publicly at /static/banner.png.
                                 Same bytes, encrypted vs clear = a known-plaintext attack.
                                 bkcrack recovers the keystream and decrypts the bundle.
                                 (flag3, inside the archive)

  4. Password cracking        -> the decrypted bundle also holds vault_hashes.txt, a
     (salted sha512crypt)        sha512crypt ($6$) credential for `svc_deploy`. Crack it
                                 (john/hashcat + rockyou) and POST the plaintext to
                                 /api/vault/unlock to release the deploy vault.  (flag4)

Discovery note (author): nothing is handed to you via robots.txt. The API endpoints, the
cookie name, and the token shape live in the inline <script> on the landing page and in
your Burp history — read it the way you'd read a real SPA's bundle. That's the recon.

The fixes (see SOLUTION.md): pin the accepted algorithm and reject alg:none / verify the
signature with a fixed key (1); never render user input as a template — pass it as data to
a static template, or sandbox/escape it (2); use AES-encrypted archives (WinZip/AE) instead
of legacy ZipCrypto, which is broken against known plaintext (3); rate-limit + use a slow
KDF and don't ship credential stores in downloadable artifacts (4).
"""
import os
import hmac
import json
import base64
import hashlib
from crypt import crypt

from flask import (Flask, request, redirect, jsonify, make_response,
                   render_template_string, send_from_directory, Response)

app = Flask(__name__)

ARTIFACT_DIR = "/app/artifacts"

# ------------------------------------------------------------------ flags -----------
FLAG1 = "FLAG{jwt_4lg_n0n3_f0rg3d_4dm1n}"
FLAG2 = "FLAG{ssti_j1nj4_c0nf1g_l34k3d}"
FLAG3 = "FLAG{z1pcrypt0_kn0wn_pl41nt3xt_bkcr4ck}"
FLAG4 = "FLAG{s4lt3d_sh4512crypt_r0cky0u_cr4ck3d}"

# The JWT signing key. A *real* one exists so guest tokens are genuinely signed — the bug
# is that the verifier will happily accept an UNSIGNED (alg:none) token as well.
JWT_KEY = os.environ.get("JWT_KEY", "cogwheel-ci-prod-signing-key-9f13")

# The encrypted artifact bundle's filename is intentionally unguessable and is NOT listed
# anywhere the UI exposes — you only learn it by dumping the config via the SSTI (stage 2).
app.config["FLAG2"] = FLAG2
app.config["ARTIFACT_BUNDLE"] = os.environ.get("ARTIFACT_BUNDLE", "ci-artifacts-8f2a91.zip")
app.config["ARTIFACT_NOTE"] = ("bundle is ZipCrypto-encrypted; one member (banner.png) is "
                               "also published under /static for the build header")

# sha512crypt credential for the deploy vault. The SAME line ships inside the encrypted
# bundle (vault_hashes.txt); cracking it is stage 4.
VAULT_USER = "svc_deploy"
VAULT_HASH = ("$6$lcr81F0J9j6GF7St$yn81fz57ZScNYp1a0RijnKG4Zoy.D31yNBGJoyDsNLR7KP"
              "QdD7Ykhg4I3zTpkoKOyJVHnQ4T4b0JfkoJOCPoH1")


# ------------------------------------------------------------------ JWT (hand-rolled) --
def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def make_token(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def verify_token(token):
    # VULN #1 (JWT alg:none): the header's declared algorithm is trusted. When it says
    # "none", the signature segment is ignored and the payload is accepted as-is — so an
    # attacker can rewrite the claims (role -> admin) and simply strip the signature.
    try:
        h, p, s = token.split(".")
        header = json.loads(_b64u_dec(h))
        payload = json.loads(_b64u_dec(p))
    except Exception:
        return None
    alg = header.get("alg", "")
    if alg == "none":
        return payload                      # <-- unsigned token accepted
    if alg == "HS256":
        expected = hmac.new(JWT_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if hmac.compare_digest(_b64u(expected), s):
            return payload
    return None


def current_claims():
    tok = request.cookies.get("cog_session")
    return verify_token(tok) if tok else None


# ------------------------------------------------------------------ layout ----------
SHELL = """
<!doctype html><html><head><title>Cogwheel CI</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:780px;margin:34px auto;padding:0 16px;color:#12212b;background:#eef2f6}
 header{border-bottom:2px solid #4338ca;padding-bottom:8px;margin-bottom:18px;display:flex;align-items:center;gap:12px}
 header img{height:26px;border-radius:4px}
 .card{background:#fff;border:1px solid #d7dde6;border-radius:8px;padding:16px;margin:12px 0}
 a{color:#4338ca} input,textarea{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 textarea{min-height:70px;font-family:ui-monospace,monospace}
 label{display:block;font-size:13px;margin-top:8px;color:#41525f}
 .btn{background:#4338ca;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .muted{color:#5c6b78;font-size:13px} code{background:#e5e9f0;padding:1px 4px;border-radius:3px}
 .flag{background:#1e1b4b;color:#c7d2fe;padding:10px;border-radius:6px;font-family:ui-monospace,monospace;word-break:break-all}
 pre{background:#12212b;color:#dbeafe;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
 nav a{margin-right:10px} .err{color:#b00020}
</style></head><body>
<header><img src="/static/banner.png" alt="build header">
<h2>⚙️ Cogwheel CI <span class="muted">internal build &amp; artifact server</span></h2></header>
<nav>{{ nav|safe }}</nav>
{{ body|safe }}
</body></html>
"""


def page(body, nav=""):
    return render_template_string(SHELL, body=body, nav=nav)


def nav_for(c):
    links = '<a href="/">home</a>'
    if c and c.get("role") == "admin":
        links += ' · <a href="/admin">admin console</a>'
    return links


# ------------------------------------------------------------------ pages -----------
@app.route("/")
def index():
    claims = current_claims()
    body = """
    <div class="card">
      <h3>Build status</h3>
      <p class="muted">You're browsing as <b id="who">…</b>. The <b>admin console</b>
      (<code>/admin</code>) is restricted to CI administrators.</p>
      <p class="muted">Guest sessions are issued automatically — check your
      <code>cog_session</code> cookie.</p>
    </div>
    <script>
    // Session state comes from /api/whoami, which reads your signed cog_session JWT.
    fetch('/api/whoami').then(r=>r.json()).then(j=>{
      document.getElementById('who').textContent = (j.user||'?') + ' (role: ' + (j.role||'?') + ')';
    });
    </script>
    """
    resp = make_response(page(body, nav=nav_for(claims)))
    if not claims:
        # hand out a genuinely-signed guest token
        resp.set_cookie("cog_session", make_token({"user": "guest", "role": "viewer"}))
    return resp


@app.route("/api/whoami")
def whoami():
    c = current_claims() or {}
    return jsonify(user=c.get("user"), role=c.get("role"))


@app.route("/admin")
def admin():
    c = current_claims()
    if not c or c.get("role") != "admin":
        return page('<div class="card"><h3 class="err">403 — admin console</h3>'
                    '<p class="muted">Your token does not carry the <code>admin</code> '
                    'role.</p></div>', nav=nav_for(c)), 403
    body = f"""
    <div class="card">
      <h3>🔧 Admin console</h3>
      <p>Token accepted with <code>role=admin</code>. Checkpoint one:</p>
      <div class="flag">{FLAG1}</div>
    </div>
    <div class="card">
      <h3>Build announcement — preview</h3>
      <p class="muted">Type a message; the server renders it into the announcement banner
      template and returns the HTML. Supports the usual template variables.</p>
      <label>Announcement template</label>
      <textarea id="tpl">Deploy #{{{{ build }}}} is green ✅</textarea>
      <p><button class="btn" onclick="render()">Preview</button></p>
      <pre id="out" style="display:none"></pre>
    </div>
    <div class="card">
      <h3>Artifact download</h3>
      <p class="muted">Fetch a build artifact by name from the artifact store.</p>
      <label>Artifact name</label><input id="an" placeholder="e.g. build.log">
      <p><button class="btn" onclick="dl()">Download</button></p>
      <p id="dm" class="muted"></p>
    </div>
    <div class="card">
      <h3>Deploy vault</h3>
      <p class="muted">Release the deploy vault with the <code>svc_deploy</code> password.</p>
      <label>Password</label><input id="vp" type="password">
      <p><button class="btn" onclick="unlock()">Unlock</button></p>
      <p id="vm" class="muted"></p>
    </div>
    <script>
    async function render(){{
      const r = await fetch('/api/render', {{method:'POST',
        headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{ template: document.getElementById('tpl').value }})}});
      const j = await r.json();
      const o = document.getElementById('out'); o.style.display='block';
      o.textContent = j.ok ? j.rendered : (j.error||'error');
    }}
    async function dl(){{
      const name = document.getElementById('an').value;
      const r = await fetch('/download?name=' + encodeURIComponent(name));
      document.getElementById('dm').textContent =
        r.ok ? ('OK — ' + r.headers.get('content-length') + ' bytes (save with curl -OJ)')
             : ('failed: ' + r.status);
    }}
    async function unlock(){{
      const r = await fetch('/api/vault/unlock', {{method:'POST',
        headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{ password: document.getElementById('vp').value }})}});
      const j = await r.json();
      document.getElementById('vm').innerHTML = j.ok
        ? ('<span class="flag">'+j.flag+'</span>') : (j.error||'wrong password');
    }}
    </script>
    """
    return page(body, nav=nav_for(c))


@app.route("/api/render", methods=["POST"])
def api_render():
    c = current_claims()
    if not c or c.get("role") != "admin":
        return jsonify(ok=False, error="admin only"), 403
    tpl = (request.get_json(silent=True) or {}).get("template", "")
    # VULN #2 (SSTI): the admin-supplied string is compiled and rendered as a Jinja2
    # template with a live context. `{{ ... }}` expressions execute server-side — dumping
    # config, reaching Python builtins, reading files, etc.
    try:
        rendered = render_template_string(tpl, build=42, status="green")
    except Exception as e:
        return jsonify(ok=False, error=f"render error: {e}")
    return jsonify(ok=True, rendered=rendered)


@app.route("/download")
def download():
    c = current_claims()
    if not c or c.get("role") != "admin":
        return jsonify(ok=False, error="admin only"), 403
    name = os.path.basename(request.args.get("name", ""))   # store is flat; no traversal here
    if not name:
        return "supply ?name=", 400
    path = os.path.join(ARTIFACT_DIR, name)
    if not os.path.isfile(path):
        return "no such artifact", 404
    return send_from_directory(ARTIFACT_DIR, name, as_attachment=True)


@app.route("/api/vault/unlock", methods=["POST"])
def vault_unlock():
    c = current_claims()
    if not c or c.get("role") != "admin":
        return jsonify(ok=False, error="admin only"), 403
    pw = (request.get_json(silent=True) or {}).get("password", "")
    # Verify against the sha512crypt hash the learner cracked out of the bundle.
    if pw and crypt(pw, VAULT_HASH) == VAULT_HASH:
        return jsonify(ok=True, flag=FLAG4)
    return jsonify(ok=False, error="wrong password")


@app.route("/static/<path:f>")
def static_files(f):
    return send_from_directory("/app/static", f)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
