"""
Ledgr — intermediate web CTF (Broken Access Control / IDOR).

Deliberately vulnerable. One primitive — broken access control — drilled in three
escalating flavours so it becomes automatic:

  1. Sequential IDOR              -> /invoice/<id> fetches an invoice by id and renders
                                     it WITHOUT checking it belongs to you. You are a
                                     valid, logged-in user; the server just never asks
                                     "is this yours?". Change the number, read a stranger's
                                     invoice. (flag1)

  2. IDOR behind an "opaque" ref  -> /statement?token=<base64> decodes to `acct:<uid>`
                                     and renders that account's statement, again with no
                                     ownership check. The token LOOKS random but is just
                                     base64 — decode it, change the uid, re-encode.
                                     Obfuscation is not authorisation. (flag2)

  3. Broken function-level authz  -> /admin (the page) correctly refuses non-admins with
                                     403. But /admin/export (the action behind the button)
                                     forgets to check role at all. The UI hid the button;
                                     the endpoint is wide open. Force-browse straight to
                                     the action. (flag3)

The session itself is NOT the bug: `sid` is a proper server-side, httpOnly, random
session id. You are correctly *authenticated* as a low-privilege customer. Every flag
is a failure of *authorisation* — the app never checks whether an authenticated user is
allowed to touch a given object or function.

NOTE(author): the fix for all three is the same shape — enforce an ownership/role check
on the server for EVERY object and EVERY action, not just the ones the UI happens to
link. Hiding a button, and encoding an id, are not access control. See SOLUTION.md.
"""
import os
import base64
import secrets
from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)

FLAG1 = "FLAG{id0r_s3qu3nt14l_1nv01c3}"        # in another customer's invoice
FLAG2 = "FLAG{id0r_b64_t0k3n_n0t_4uthz}"       # in the admin's account statement
FLAG3 = "FLAG{br0k3n_funcl3v3l_4dm1n_3xp0rt}"  # behind the unprotected admin export

# ---- users (server-side; you log in as alice, a normal customer) -------------------
# uid -> record. Passwords here only so the login page has something real to check.
USERS = {
    1: {"user": "admin", "pw": secrets.token_hex(16), "role": "admin", "name": "Ledgr Admin"},
    2: {"user": "alice", "pw": "hunter2",              "role": "user",  "name": "Alice Nguyen"},
    3: {"user": "bob",   "pw": secrets.token_hex(16),  "role": "user",  "name": "Bob Ortiz"},
    4: {"user": "carol", "pw": secrets.token_hex(16),  "role": "user",  "name": "Carol Diaz"},
}
NAME_TO_UID = {u["user"]: uid for uid, u in USERS.items()}

# ---- invoices (flag1 lives in one you don't own) -----------------------------------
# id -> {owner uid, customer, date, lines:[(desc, cents)], note}
INVOICES = {
    1001: {"owner": 3, "customer": "Bob Ortiz",   "date": "2026-05-02",
           "lines": [("Ledgr Pro — annual", 24000), ("Priority support add-on", 6000)],
           "note": "Internal: comp'd Q2 credit issued. " + FLAG1},
    1002: {"owner": 2, "customer": "Alice Nguyen", "date": "2026-06-11",
           "lines": [("Ledgr Pro — monthly", 2000), ("Extra seats (2)", 1600)],
           "note": "Thanks for being a customer!"},
    1003: {"owner": 4, "customer": "Carol Diaz",  "date": "2026-06-14",
           "lines": [("Ledgr Starter — monthly", 900)],
           "note": "Trial converted."},
    1004: {"owner": 3, "customer": "Bob Ortiz",   "date": "2026-06-30",
           "lines": [("Overage — API calls", 1150)],
           "note": "Auto-generated."},
    1005: {"owner": 2, "customer": "Alice Nguyen", "date": "2026-07-09",
           "lines": [("Ledgr Pro — monthly", 2000)],
           "note": "Auto-generated."},
}

# ---- account statements, addressed by uid (flag2 in the admin's) -------------------
STATEMENTS = {
    1: {"name": "Ledgr Admin", "balance": 0,
        "detail": "Master billing account. API service key: " + FLAG2},
    2: {"name": "Alice Nguyen", "balance": 3600,
        "detail": "Open balance across invoices #1002, #1005."},
    3: {"name": "Bob Ortiz", "balance": 1150,
        "detail": "Open balance across invoices #1001, #1004."},
    4: {"name": "Carol Diaz", "balance": 900,
        "detail": "Open balance across invoice #1003."},
}

# ---- sessions: random sid -> uid (proper server-side session; NOT the vuln) ---------
SESSIONS = {}


def current_uid():
    return SESSIONS.get(request.cookies.get("sid"))


def money(cents):
    return f"${cents/100:,.2f}"


def b64token(uid):
    return base64.urlsafe_b64encode(f"acct:{uid}".encode()).decode()


# ---------------------------------------------------------------- shared layout -----
SHELL = """
<!doctype html><html><head><title>Ledgr</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:780px;margin:36px auto;padding:0 16px;color:#122}
 header{border-bottom:2px solid #0f766e;padding-bottom:8px;margin-bottom:18px}
 .card{background:#f2fbf9;border:1px solid #cdeae4;border-radius:8px;padding:16px;margin:12px 0}
 .flag{background:#04302b;color:#a9f0e2;padding:8px 10px;border-radius:6px;font-family:monospace}
 a{color:#0f766e} input{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#0f766e;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .btn.warn{background:#a3324a}
 .err{color:#b00020} code{background:#e7f4f1;padding:1px 4px;border-radius:3px}
 table{border-collapse:collapse;width:100%;margin:6px 0} td,th{border-bottom:1px solid #dceee9;padding:6px;text-align:left}
 .muted{color:#5a6b68;font-size:13px} .who{font-weight:bold;color:#0f766e}
 nav a{margin-right:10px}
</style></head><body>
<header><h2>📒 Ledgr <span class="muted">simple billing for small teams</span></h2>
<nav>{{ nav|safe }}</nav></header>
{{ body|safe }}
</body></html>
"""


def page(body, nav=None):
    if nav is None:
        uid = current_uid()
        if uid:
            nav = (f'<a href="/dashboard">dashboard</a> · '
                   f'<span class="muted">signed in as <span class="who">{USERS[uid]["user"]}</span> '
                   f'({USERS[uid]["role"]})</span> · <a href="/logout">logout</a>')
        else:
            nav = '<a href="/">home</a>'
    return render_template_string(SHELL, body=body, nav=nav)


def require_login():
    """Returns uid if logged in, else None. Endpoints below use this to force a valid
    session — but then DO NOT check ownership/role. That gap is the whole CTF."""
    return current_uid()


# ---------------------------------------------------------------- routes ------------
@app.route("/")
def home():
    if current_uid():
        return redirect("/dashboard")
    body = """
    <div class="card">
      <h3>Welcome to Ledgr</h3>
      <p class="muted">Sign in to view your invoices and account statement.</p>
      <form method="post" action="/login">
        <label>Username</label><input name="user" value="alice">
        <label>Password</label><input name="pw" type="password" value="hunter2">
        <button class="btn">Sign in</button>
      </form>
    </div>
    <div class="card">
      <p class="muted">🔑 <b>Demo account (pre-filled):</b> <code>alice</code> /
      <code>hunter2</code> — a normal customer.</p>
    </div>
    """
    return page(body, nav='<a href="/">home</a>')


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("user", "")
    pw = request.form.get("pw", "")
    uid = NAME_TO_UID.get(u)
    if uid and USERS[uid]["pw"] == pw:
        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = uid
        resp = make_response(redirect("/dashboard"))
        # Proper session cookie: server-side lookup, httpOnly. This is NOT the bug.
        resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
        return resp
    body = ('<div class="card"><p class="err">Bad username or password.</p>'
            '<a href="/">back</a></div>')
    return page(body, nav='<a href="/">home</a>')


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get("sid"), None)
    resp = make_response(redirect("/"))
    resp.delete_cookie("sid")
    return resp


@app.route("/dashboard")
def dashboard():
    uid = require_login()
    if not uid:
        return redirect("/")
    me = USERS[uid]
    mine = [(iid, inv) for iid, inv in INVOICES.items() if inv["owner"] == uid]
    rows = "".join(
        f'<tr><td><a href="/invoice/{iid}">#{iid}</a></td>'
        f'<td>{inv["date"]}</td>'
        f'<td>{money(sum(c for _, c in inv["lines"]))}</td></tr>'
        for iid, inv in sorted(mine)
    )
    body = f"""
    <div class="card">
      <h3>Hi {me['name']}</h3>
      <p class="muted">Your role: <b>{me['role']}</b>. Account #{uid}.</p>
    </div>
    <div class="card">
      <h3>Your invoices</h3>
      <table><tr><th>Invoice</th><th>Date</th><th>Total</th></tr>{rows}</table>
    </div>
    <div class="card">
      <h3>Account statement</h3>
      <p class="muted">Download your statement (secure tokenised link):</p>
      <p><a href="/statement?token={b64token(uid)}">📄 /statement?token={b64token(uid)}</a></p>
    </div>
    <!-- ops note: admin tools moved under /admin/ — see robots.txt, keep them out of search -->
    """
    return page(body)


@app.route("/invoice/<int:iid>")
def invoice(iid):
    uid = require_login()
    if not uid:
        return redirect("/")
    inv = INVOICES.get(iid)
    if not inv:
        return page('<div class="card"><p class="err">No such invoice.</p></div>'), 404
    # VULN #1: fetched by id, rendered with NO check that inv["owner"] == uid.
    lines = "".join(
        f'<tr><td>{d}</td><td>{money(c)}</td></tr>' for d, c in inv["lines"]
    )
    total = money(sum(c for _, c in inv["lines"]))
    body = f"""
    <div class="card">
      <h3>Invoice #{iid}</h3>
      <p class="muted">Billed to <b>{inv['customer']}</b> · {inv['date']}</p>
      <table><tr><th>Item</th><th>Amount</th></tr>{lines}
        <tr><th>Total</th><th>{total}</th></tr></table>
      <p class="muted">Note: {inv['note']}</p>
      <p><a href="/dashboard">← back</a></p>
    </div>
    """
    return page(body)


@app.route("/statement")
def statement():
    uid = require_login()
    if not uid:
        return redirect("/")
    token = request.args.get("token", "")
    try:
        ref = base64.urlsafe_b64decode(token.encode()).decode()
        assert ref.startswith("acct:")
        target = int(ref.split(":", 1)[1])
    except Exception:
        return page('<div class="card"><p class="err">Invalid statement token.</p>'
                    '<a href="/dashboard">back</a></div>'), 400
    st = STATEMENTS.get(target)
    if not st:
        return page('<div class="card"><p class="err">No statement for that account.</p></div>'), 404
    # VULN #2: the token decodes to an account id; we serve it with NO check that it is
    # the caller's own account. The base64 wrapper is not authorisation.
    body = f"""
    <div class="card">
      <h3>Account statement — {st['name']} (account #{target})</h3>
      <p>Open balance: <b>{money(st['balance'])}</b></p>
      <p class="muted">{st['detail']}</p>
      <p><a href="/dashboard">← back</a></p>
    </div>
    """
    return page(body)


@app.route("/admin")
def admin():
    uid = require_login()
    if not uid:
        return redirect("/")
    # The PAGE is guarded correctly...
    if USERS[uid]["role"] != "admin":
        return page('<div class="card"><p class="err">403 — Admins only.</p>'
                    '<a href="/dashboard">back</a></div>'), 403
    body = """
    <div class="card">
      <h3>Admin console</h3>
      <form method="post" action="/admin/export">
        <button class="btn warn">Export all accounts</button>
      </form>
    </div>
    """
    return page(body)


@app.route("/admin/export", methods=["GET", "POST"])
def admin_export():
    uid = require_login()
    if not uid:
        return redirect("/")
    # VULN #3: broken function-level authorisation. The /admin PAGE checks role, but
    # this ACTION — the thing that actually leaks data — never does. Any logged-in user
    # who reaches this endpoint gets the dump.
    rows = "".join(
        f'<tr><td>#{i}</td><td>{u["user"]}</td><td>{u["role"]}</td>'
        f'<td>{USERS[i]["name"]}</td></tr>'
        for i, u in USERS.items()
    )
    body = f"""
    <div class="card">
      <h3>Account export</h3>
      <table><tr><th>ID</th><th>User</th><th>Role</th><th>Name</th></tr>{rows}</table>
      <p class="muted">Master API service key: <span class="flag">{FLAG3}</span></p>
      <p><a href="/dashboard">← back</a></p>
    </div>
    """
    return page(body)


@app.route("/robots.txt")
def robots():
    # Ironically leaks the sensitive path it's trying to hide from crawlers.
    return ("User-agent: *\nDisallow: /admin/\nDisallow: /admin/export\n",
            200, {"Content-Type": "text/plain"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
