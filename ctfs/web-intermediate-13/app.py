"""
Sesame — intermediate web CTF (Broken Authentication).

Deliberately vulnerable. One primitive — broken authentication — drilled in three
escalating flavours so it becomes automatic. Where Ledgr (CTF 12) was broken *authz*
("the app didn't check what you're allowed to do"), this box is broken *authn* ("the app
didn't properly verify *who you are*").

  1. Predictable password-reset token -> /reset accepts token == md5(username). The reset
                                         link for YOUR account leaks your token (dev
                                         mode), so you can reverse the algorithm and forge
                                         the token for someone else. Take over the admin.
                                         (flag1)

  2. JWT alg:none forgery              -> the `session` cookie is a JWT. The verifier
                                         accepts alg:"none" (unsigned) tokens. Forge one
                                         claiming a role no real account has
                                         (`superadmin`) to reach /console. (flag2)

  3. Leftover debug endpoint           -> a diagnostics endpoint shipped to "prod" with no
                                         auth. It isn't linked in the UI and there is NO
                                         robots.txt — you find it by reading the served
                                         client-side JS (/static/sesame.js) for endpoint
                                         references. (flag3)

NOTE(author): fixes — random single-use reset tokens stored server-side (never derived
from a username); a JWT library that pins the algorithm and rejects alg:none / verifies
the signature; and no debug/diagnostic endpoints in production (and auth on everything
regardless). See SOLUTION.md.
"""
import os
import json
import hmac
import base64
import hashlib
import secrets
from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)

FLAG1 = "FLAG{pr3d1ct4bl3_r3s3t_t0k3n_md5}"     # admin account takeover via reset
FLAG2 = "FLAG{jwt_4lg_n0n3_f0rg3d_sup3r}"       # alg:none JWT forgery
FLAG3 = "FLAG{d3bug_3ndp01nt_l3ft_1n_pr0d}"     # leftover diagnostics endpoint

# HS256 secret for legit tokens. Strong + secret on purpose: the bug is NOT a weak
# secret you can crack — it's that the verifier also accepts alg:"none".
JWT_SECRET = secrets.token_bytes(32)

# uid keyed users. admin's password is random (you can't just log in as admin — you must
# take the account over via the reset flaw). No 'superadmin' account exists anywhere:
# that role is only reachable by forging a token.
USERS = {
    "alice": {"pw": "hunter2",             "role": "user",  "name": "Alice Nguyen"},
    "bob":   {"pw": secrets.token_hex(16), "role": "user",  "name": "Bob Ortiz"},
    "admin": {"pw": secrets.token_hex(16), "role": "admin", "name": "Site Admin"},
}


def reset_token(username):
    # VULN #1: token derived from a public value. Predictable => forgeable.
    return hashlib.md5(username.encode()).hexdigest()


# ---- hand-rolled JWT so the alg:none acceptance is explicit ------------------------
def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def jwt_sign(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def jwt_verify(token):
    try:
        parts = token.split(".")
        h, p = parts[0], parts[1]
        s = parts[2] if len(parts) > 2 else ""
        header = json.loads(_b64u_dec(h))
        payload = json.loads(_b64u_dec(p))
        alg = header.get("alg", "")
        if alg.lower() == "none":
            return payload          # VULN #2: unsigned tokens accepted, no verification
        expected = _b64u(hmac.new(JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, s):
            return payload
    except Exception:
        return None
    return None


def current():
    tok = request.cookies.get("session", "")
    return jwt_verify(tok) if tok else None


# ---------------------------------------------------------------- shared layout -----
SHELL = """
<!doctype html><html><head><title>Sesame</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:36px auto;padding:0 16px;color:#1a1a2e}
 header{border-bottom:2px solid #4338ca;padding-bottom:8px;margin-bottom:18px}
 .card{background:#f4f4ff;border:1px solid #d7d7f5;border-radius:8px;padding:16px;margin:12px 0}
 .flag{background:#1e1b4b;color:#c7d2fe;padding:8px 10px;border-radius:6px;font-family:monospace}
 a{color:#4338ca} input{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#4338ca;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .err{color:#b00020} .ok{color:#0a7d33}
 code{background:#e6e6fb;padding:1px 4px;border-radius:3px;word-break:break-all}
 .muted{color:#5a5a72;font-size:13px} .who{font-weight:bold;color:#4338ca}
 nav a{margin-right:10px}
</style></head><body>
<header><h2>🔐 Sesame <span class="muted">single sign-on for your team</span></h2>
<nav>{{ nav|safe }}</nav></header>
{{ body|safe }}
<script src="/static/sesame.js"></script>
</body></html>
"""


def page(body, nav=None):
    if nav is None:
        c = current()
        if c:
            nav = (f'<a href="/dashboard">dashboard</a> · '
                   f'<span class="muted">signed in as <span class="who">{c.get("user")}</span> '
                   f'({c.get("role")})</span> · <a href="/logout">logout</a>')
        else:
            nav = '<a href="/">home</a> · <a href="/reset">forgot password?</a>'
    return render_template_string(SHELL, body=body, nav=nav)


# ---------------------------------------------------------------- routes ------------
@app.route("/")
def home():
    if current():
        return redirect("/dashboard")
    body = """
    <div class="card">
      <h3>Sign in</h3>
      <form method="post" action="/login">
        <label>Username</label><input name="user" value="alice">
        <label>Password</label><input name="pw" type="password" value="hunter2">
        <button class="btn">Sign in</button>
      </form>
      <p class="muted">Forgot your password? <a href="/reset">Reset it.</a></p>
    </div>
    <div class="card"><p class="muted">🔑 <b>Demo account (pre-filled):</b>
      <code>alice</code> / <code>hunter2</code>.</p></div>
    """
    return page(body, nav='<a href="/">home</a> · <a href="/reset">forgot password?</a>')


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("user", "")
    pw = request.form.get("pw", "")
    rec = USERS.get(u)
    if rec and rec["pw"] == pw:
        token = jwt_sign({"user": u, "role": rec["role"]})
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session", token, samesite="Lax")
        return resp
    return page('<div class="card"><p class="err">Bad username or password.</p>'
                '<a href="/">back</a></div>', nav='<a href="/">home</a>')


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.route("/dashboard")
def dashboard():
    c = current()
    if not c:
        return redirect("/")
    u = c.get("user", "?")
    role = c.get("role", "?")
    body = f"""
    <div class="card">
      <h3>Welcome, {u}</h3>
      <p class="muted">Role: <b>{role}</b>.</p>
    </div>
    <div class="card">
      <h3>Account recovery</h3>
      <p class="muted">Lost access on another device? Here's your personal reset link
      (dev build shows it inline instead of emailing):</p>
      <p><code>/reset?user={u}&amp;token={reset_token(u)}</code></p>
    </div>
    """
    return page(body)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        # token/user may be prefilled from a link
        u = request.args.get("user", "")
        t = request.args.get("token", "")
        body = f"""
        <div class="card">
          <h3>Reset password</h3>
          <form method="post">
            <label>Username</label><input name="user" value="{u}">
            <label>Reset token</label><input name="token" value="{t}">
            <label>New password</label><input name="newpw" type="password">
            <button class="btn">Set new password</button>
          </form>
        </div>
        """
        return page(body, nav='<a href="/">home</a>')
    u = request.form.get("user", "")
    t = request.form.get("token", "")
    newpw = request.form.get("newpw", "")
    rec = USERS.get(u)
    # VULN #1: any caller who can produce md5(username) may reset that account.
    if rec and t == reset_token(u) and newpw:
        rec["pw"] = newpw
        extra = ""
        if u == "admin":
            extra = (f'<p class="ok">Admin account recovered. Confirmation code: '
                     f'<span class="flag">{FLAG1}</span></p>')
        body = (f'<div class="card"><p class="ok">Password for <b>{u}</b> updated. '
                f'You can now sign in.</p>{extra}<a href="/">sign in</a></div>')
        return page(body, nav='<a href="/">home</a>')
    return page('<div class="card"><p class="err">Invalid username or reset token.</p>'
                '<a href="/reset">try again</a></div>', nav='<a href="/">home</a>')


@app.route("/console")
def console():
    c = current()
    if not c:
        return redirect("/")
    # gated on a role that NO real account has -> only a forged token gets in
    if c.get("role") != "superadmin":
        return page('<div class="card"><p class="err">403 — superadmin only.</p>'
                    '<a href="/dashboard">back</a></div>'), 403
    body = (f'<div class="card"><h3>Root console</h3>'
            f'<p>Master recovery key: <span class="flag">{FLAG2}</span></p>'
            f'<a href="/dashboard">back</a></div>')
    return page(body)


@app.route("/static/sesame.js")
def sesame_js():
    # Served to every page. A leftover diagnostics reference lives here — reading this
    # is how you discover /api/diag (no robots.txt in this box).
    js = """// Sesame front-end bootstrap
(function () {
  // session cookie is a JWT; server issues it on login.
  var api = { base: '' };

  // TODO(remove before GA): diagnostics endpoint used during the SSO migration.
  //   GET /api/diag  -> live build info + session dump (no auth gate yet!)
  var DIAG = api.base + '/api/diag';
  var DEBUG = false;
  if (DEBUG) {
    fetch(DIAG).then(function (r) { return r.text(); }).then(function (t) {
      console.log('[sesame:diag]', t);
    });
  }

  // normal UI wiring below…
  document.addEventListener('DOMContentLoaded', function () {});
})();
"""
    return js, 200, {"Content-Type": "application/javascript"}


@app.route("/api/diag")
def diag():
    # VULN #3: diagnostics endpoint left enabled with no authentication. Not linked in
    # any page — discoverable only by reading sesame.js (or fuzzing).
    payload = {
        "service": "sesame-sso",
        "build": "2026.07.1-rc3",
        "debug": True,
        "note": "internal diagnostics — remove before GA",
        "recovery_key": FLAG3,
        "users_loaded": list(USERS.keys()),
    }
    return json.dumps(payload, indent=2), 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
