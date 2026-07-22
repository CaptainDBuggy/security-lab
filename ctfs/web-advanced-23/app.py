"""
Mint — Advanced Web CTF (challenge 23)

Three-flag chain using three distinct vulnerability classes:
JavaScript source review  →  Race condition (TOCTOU)  →  Predictable token forgery

1. The app bundles /static/app.js containing a reference to a hidden
   diagnostics endpoint (/api/internal/diagnostics) and its auth header.
   Accessing it returns flag1 and reveals that the transfer system has
   a non-atomic balance check.                                             (flag1)

2. The /api/transfer endpoint checks the sender's balance, then pauses
   (simulating fraud-scoring), then deducts. Sending many concurrent
   requests exploits the TOCTOU gap — coins are duplicated. Accumulate
   10,000 coins and buy Premium Status for flag2.                          (flag2)

3. The password reset system generates tokens using md5(username + ts).
   The timestamp is returned in the API response. Compute the admin's
   token, reset their password, login, and access /admin/vault.            (flag3)

Fixes:
 - Diagnostics: never ship internal endpoints or secrets in client JS.
 - Transfer: wrap check-and-deduct in a single atomic transaction with
   SELECT ... FOR UPDATE (or use database-level constraints).
 - Reset: use cryptographically random tokens (secrets.token_urlsafe),
   never derive tokens from predictable inputs.
"""

from flask import Flask, request, jsonify, session, redirect, Response
import sqlite3, secrets, os, hashlib, time

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB = "/tmp/mint.db"
FLAG1 = "FLAG{h1dd3n_3ndp01nt_js_s0urc3_r3v13w}"
FLAG2 = "FLAG{r4c3_c0nd1t10n_d0ubl3_sp3nd}"
FLAG3 = "FLAG{pr3d1ct4bl3_t0k3n_4cc0unt_t4k30v3r}"

STARTING_COINS = 500
PREMIUM_COST = 10000

reset_tokens = {}


def get_db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = get_db()
    conn.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS transactions;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 500,
            premium INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount INTEGER NOT NULL,
            ts REAL NOT NULL
        );
    """)
    admin_pass = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO users (username, password, balance, premium) VALUES (?,?,?,?)",
        ("admin", admin_pass, 999999, 1))
    conn.commit()
    conn.close()


init()


STYLE = """<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:#0a0a0a;color:#c8c8c8;padding:2rem}
h1{color:#00cc88;margin-bottom:.3rem}
.sub{color:#555;margin-bottom:1.5rem}
nav{margin-bottom:2rem}
nav a{color:#00cc88;text-decoration:none;margin-right:1.5rem}
nav a:hover{text-decoration:underline}
.card{background:#111;border:1px solid #222;border-radius:6px;padding:1.2rem;margin:.8rem 0}
.card h3{color:#00cc88;font-size:.95rem;margin-bottom:.4rem}
.card p{color:#888;font-size:.85rem;line-height:1.4}
input[type=text],input[type=password],input[type=number]{width:100%;max-width:360px;
padding:.55rem;background:#080808;color:#c8c8c8;border:1px solid #333;
border-radius:4px;font-family:monospace;margin-bottom:.8rem;display:block}
label{display:block;color:#666;font-size:.8rem;text-transform:uppercase;
margin-bottom:.2rem;letter-spacing:.04em}
button{background:#00cc88;color:#000;border:none;padding:.55rem 1.4rem;
border-radius:4px;cursor:pointer;font-weight:bold;font-family:monospace;margin-top:.3rem}
button:hover{background:#00dd99}
.result{margin-top:1rem;padding:1rem;background:#080808;border:1px solid #333;
border-radius:4px;white-space:pre-wrap;font-size:.85rem;display:none}
.muted{color:#444;font-size:.8rem;margin-top:.4rem}
.section{background:#111;border:1px solid #222;border-radius:6px;padding:1.5rem;margin:1.5rem 0}
.section h2{color:#00cc88;font-size:1rem;margin-bottom:.8rem}
#msg{margin-top:.8rem;color:#cc3333;font-size:.9rem}
.balance{font-size:2rem;color:#00cc88;font-weight:bold}
.balance-label{color:#555;font-size:.8rem;text-transform:uppercase}
.premium-badge{display:inline-block;background:#1a3320;color:#00cc88;border:1px solid #00cc88;
padding:.15rem .6rem;border-radius:3px;font-size:.75rem;text-transform:uppercase}
code{background:#1a1a1a;padding:.1rem .35rem;border-radius:3px;font-size:.85rem;color:#00cc88}
</style>"""


def nav():
    parts = ['<a href="/">Home</a>']
    if "user" in session:
        parts.append('<a href="/dashboard">Dashboard</a>')
        parts.append('<a href="/shop">Shop</a>')
        if session.get("premium"):
            parts.append('<a href="/premium">Premium</a>')
        parts.append(f'<a href="/logout">Logout ({session["user"]})</a>')
    else:
        parts.append('<a href="/login">Login</a>')
        parts.append('<a href="/register">Register</a>')
    parts.append('<a href="/forgot-password">Reset Password</a>')
    return " ".join(parts)


# ── JavaScript source (the discovery target for flag 1) ──────

JS_SOURCE = r"""// Mint Platform — app.js (build 2.3.1-d4e8f2a)
// Compiled: 2026-07-18T14:22:09Z
!function(){"use strict";

const API = '';

function formatCoins(n) {
  return n.toLocaleString() + ' MC';
}

function showError(el, msg) {
  el.style.display = 'block';
  el.style.color = '#cc3333';
  el.textContent = msg;
}

function showSuccess(el, msg) {
  el.style.display = 'block';
  el.style.color = '#33cc66';
  el.textContent = msg;
}

async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return r.json();
}

async function apiGet(path) {
  return fetch(API + path).then(r => r.json());
}

// ── authentication ───────────────────────────
async function doRegister() {
  const u = document.getElementById('u').value;
  const p = document.getElementById('p').value;
  const d = await apiPost('/api/register', {username: u, password: p});
  const el = document.getElementById('msg');
  if (d.ok) {
    showSuccess(el, 'Account created! Redirecting...');
    setTimeout(() => window.location = '/login', 1000);
  } else {
    showError(el, d.error);
  }
}

async function doLogin() {
  const u = document.getElementById('u').value;
  const p = document.getElementById('p').value;
  const d = await apiPost('/api/login', {username: u, password: p});
  if (d.ok) window.location = '/dashboard';
  else document.getElementById('msg').textContent = d.error;
}

// ── coin transfers ───────────────────────────
async function doTransfer() {
  const to = document.getElementById('to').value;
  const amt = parseInt(document.getElementById('amt').value);
  const el = document.getElementById('xfer-out');
  const d = await apiPost('/api/transfer', {to: to, amount: amt});
  if (d.ok) {
    showSuccess(el, 'Sent ' + amt + ' MC to ' + to + '. New balance: ' + d.balance);
    setTimeout(() => location.reload(), 1500);
  } else {
    showError(el, d.error);
  }
}

// ── shop ─────────────────────────────────────
async function buyPremium() {
  const d = await apiPost('/api/buy-premium', {});
  const el = document.getElementById('shop-msg');
  if (d.ok) {
    showSuccess(el, 'Premium activated!');
    setTimeout(() => window.location = '/premium', 1200);
  } else {
    showError(el, d.error);
  }
}

// ── internal monitoring (dev) ────────────────
// TODO: remove before production deploy
function _initDiagnostics() {
  if (window.__MINT_DEV__) {
    fetch('/api/internal/diagnostics', {
      headers: {
        'X-Diag-Token': 'mint-internal-2026',
        'Accept': 'application/json'
      }
    }).then(r => r.json()).then(d => {
      console.log('[mint:diag]', d);
    }).catch(() => {});
  }
}

// ── password reset ───────────────────────────
async function doForgot() {
  const u = document.getElementById('u').value;
  const d = await apiPost('/api/forgot-password', {username: u});
  const el = document.getElementById('msg');
  if (d.ok) showSuccess(el, d.message);
  else showError(el, d.error);
}

async function doReset() {
  const t = document.getElementById('token').value;
  const p = document.getElementById('p').value;
  const d = await apiPost('/api/reset-password', {token: t, password: p});
  const el = document.getElementById('msg');
  if (d.ok) {
    showSuccess(el, 'Password reset! Redirecting...');
    setTimeout(() => window.location = '/login', 1500);
  } else {
    showError(el, d.error);
  }
}

// ── expose to inline handlers ────────────────
window.doRegister = doRegister;
window.doLogin = doLogin;
window.doTransfer = doTransfer;
window.buyPremium = buyPremium;
window.doForgot = doForgot;
window.doReset = doReset;

// ── boot ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  _initDiagnostics();
});

}();
"""


# ── Pages ─────────────────────────────────────────────────────

@app.route("/static/app.js")
def static_js():
    return Response(JS_SOURCE, content_type="application/javascript")


@app.route("/")
def index():
    return (
        "<!doctype html><title>Mint — Digital Currency</title>"
        f"{STYLE}"
        "<h1>Mint</h1>"
        '<p class="sub">Digital Currency Platform</p>'
        f"<nav>{nav()}</nav>"
        '<div class="section">'
        "<h2>Welcome to Mint</h2>"
        "<p>Trade, transfer, and earn MintCoins (MC). "
        "New accounts start with 500 MC.</p>"
        '<p class="muted" style="margin-top:.8rem">'
        "Premium members unlock exclusive features and system insights.</p>"
        "</div>"
        '<script src="/static/app.js"></script>'
    )


@app.route("/register")
def register_page():
    return (
        "<!doctype html><title>Mint — Register</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Create Account</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doRegister()" style="width:100%">Register</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/login" style="color:#00cc88;text-decoration:none">'
        "Already have an account? Login</a></p></div>"
        '<script src="/static/app.js"></script>'
    )


@app.route("/login")
def login_page():
    return (
        "<!doctype html><title>Mint — Login</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Mint Login</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<label>Password</label><input id="p" type="password">'
        '<button onclick="doLogin()" style="width:100%">Sign In</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/register" style="color:#00cc88;text-decoration:none">'
        "Need an account? Register</a></p></div>"
        '<script src="/static/app.js"></script>'
    )


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?",
                        (session["user"],)).fetchone()
    txns = conn.execute(
        "SELECT * FROM transactions WHERE sender=? OR receiver=? "
        "ORDER BY ts DESC LIMIT 10",
        (session["user"], session["user"])).fetchall()
    conn.close()

    premium_badge = (' <span class="premium-badge">Premium</span>'
                     if user["premium"] else "")

    tx_rows = ""
    for t in txns:
        if t["sender"] == session["user"]:
            direction, other, color = "→", t["receiver"], "#cc3333"
        else:
            direction, other, color = "←", t["sender"], "#33cc66"
        tx_rows += (
            '<div style="padding:.4rem 0;border-bottom:1px solid #222;'
            f'font-size:.85rem"><span style="color:{color}">{direction}'
            f'</span> {other} — {t["amount"]} MC</div>')
    if not tx_rows:
        tx_rows = '<p class="muted">No transactions yet.</p>'

    return (
        "<!doctype html><title>Mint — Dashboard</title>"
        f"{STYLE}"
        "<h1>Dashboard</h1>"
        f'<p class="sub">{session["user"]}{premium_badge}</p>'
        f"<nav>{nav()}</nav>"

        '<div class="section">'
        '<p class="balance-label">Balance</p>'
        f'<p class="balance">{user["balance"]:,} MC</p>'
        "</div>"

        '<div class="section">'
        "<h2>Transfer Coins</h2>"
        '<label>Recipient</label>'
        '<input id="to" type="text" placeholder="username">'
        '<label>Amount</label>'
        '<input id="amt" type="number" placeholder="100" min="1">'
        '<button onclick="doTransfer()">Send</button>'
        '<div id="xfer-out" class="result"></div>'
        "</div>"

        '<div class="section">'
        "<h2>Recent Transactions</h2>"
        f"{tx_rows}"
        "</div>"

        '<script src="/static/app.js"></script>'
    )


@app.route("/shop")
def shop():
    if "user" not in session:
        return redirect("/login")
    conn = get_db()
    user = conn.execute("SELECT balance, premium FROM users WHERE username=?",
                        (session["user"],)).fetchone()
    conn.close()

    if user["premium"]:
        status = '<p style="color:#00cc88">You already have Premium Status.</p>'
        btn = ""
    else:
        status = (
            f'<p>Your balance: <strong>{user["balance"]:,} MC</strong></p>'
            f'<p class="muted">Premium Status costs {PREMIUM_COST:,} MC.</p>')
        btn = (f'<button onclick="buyPremium()" style="margin-top:.8rem">'
               f'Buy Premium — {PREMIUM_COST:,} MC</button>')

    return (
        "<!doctype html><title>Mint — Shop</title>"
        f"{STYLE}"
        "<h1>Shop</h1>"
        '<p class="sub">Spend your MintCoins</p>'
        f"<nav>{nav()}</nav>"

        '<div class="section">'
        "<h2>Premium Status</h2>"
        "<p>Unlock exclusive analytics and system insights.</p>"
        f"{status}{btn}"
        '<div id="shop-msg"></div>'
        "</div>"

        '<script src="/static/app.js"></script>'
    )


@app.route("/premium")
def premium_page():
    if "user" not in session:
        return redirect("/login")
    conn = get_db()
    user = conn.execute("SELECT premium FROM users WHERE username=?",
                        (session["user"],)).fetchone()
    conn.close()
    if not user["premium"]:
        return redirect("/shop")

    return (
        "<!doctype html><title>Mint — Premium</title>"
        f"{STYLE}"
        "<h1>Premium Zone</h1>"
        '<p class="sub">Exclusive access</p>'
        f"<nav>{nav()}</nav>"

        '<div class="section">'
        "<h2>Congratulations</h2>"
        f'<p style="color:#00cc88;font-size:1.1rem;margin-bottom:.8rem">'
        f"{FLAG2}</p>"
        "<p>You exploited a race condition in the transfer system. The "
        "balance check and deduction are not atomic — concurrent "
        "requests all pass the check before any deduction occurs, "
        "duplicating coins out of thin air.</p>"
        "</div>"

        '<div class="section">'
        "<h2>System Intelligence</h2>"
        '<p class="muted">Premium analytics — internal deployment notes:</p>'
        '<div class="card">'
        "<h3>Password Reset Service</h3>"
        "<p>The emergency password reset system is active on this deployment. "
        "Token generation uses <code>md5</code> hashing over predictable "
        "inputs (the username and request timestamp). The API response at "
        "<code>/api/forgot-password</code> includes the exact request "
        "timestamp in the <code>requested_at</code> field. "
        "Admin account: <strong>admin</strong>.</p>"
        "</div>"
        "</div>"

        '<script src="/static/app.js"></script>'
    )


@app.route("/forgot-password")
def forgot_page():
    return (
        "<!doctype html><title>Mint — Forgot Password</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Reset Password</h1>'
        '<label>Username</label><input id="u" type="text" autocomplete="off">'
        '<button onclick="doForgot()" style="width:100%">Request Reset</button>'
        '<div id="msg"></div>'
        '<p style="text-align:center;margin-top:1.5rem">'
        '<a href="/login" style="color:#00cc88;text-decoration:none">'
        "Back to Login</a></p></div>"
        '<script src="/static/app.js"></script>'
    )


@app.route("/reset-password")
def reset_page():
    return (
        "<!doctype html><title>Mint — Reset Password</title>"
        f"{STYLE}"
        '<div style="max-width:380px;margin:4rem auto">'
        '<h1 style="text-align:center;margin-bottom:1.5rem">Set New Password</h1>'
        '<label>Reset Token</label>'
        '<input id="token" type="text" autocomplete="off" placeholder="paste token">'
        '<label>New Password</label><input id="p" type="password">'
        '<button onclick="doReset()" style="width:100%">Reset Password</button>'
        '<div id="msg"></div></div>'
        '<script src="/static/app.js"></script>'
    )


@app.route("/admin/vault")
def admin_vault():
    if session.get("user") != "admin":
        return jsonify(ok=False, error="admin access required"), 403
    return (
        "<!doctype html><title>Mint — Admin Vault</title>"
        f"{STYLE}"
        "<h1>Admin Vault</h1>"
        '<p class="sub">Restricted access</p>'
        f"<nav>{nav()}</nav>"

        '<div class="section">'
        "<h2>Vault Master Key</h2>"
        f'<p style="color:#00cc88;font-size:1.1rem;margin-bottom:.8rem">'
        f"{FLAG3}</p>"
        "<p>You forged a password reset token by exploiting predictable "
        "token generation. The system used "
        "<code>md5(username + timestamp)</code> and leaked the exact "
        "timestamp in the API response — allowing you to compute the "
        "token without any email access.</p>"
        "</div>"

        '<script src="/static/app.js"></script>'
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── API ───────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify(ok=False, error="username and password required"), 400
    if len(username) > 40:
        return jsonify(ok=False, error="username too long"), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, balance, premium) "
            "VALUES (?,?,?,?)",
            (username, password, STARTING_COINS, 0))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify(ok=False, error="username already taken"), 400
    conn.close()
    return jsonify(ok=True, user=username)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u = data.get("username", "")
    p = data.get("password", "")
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, balance, premium FROM users "
        "WHERE username=? AND password=?",
        (u, p)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False, error="invalid credentials"), 401
    session["user_id"] = row["id"]
    session["user"] = row["username"]
    session["premium"] = bool(row["premium"])
    return jsonify(ok=True, user=row["username"])


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    if "user" not in session:
        return jsonify(ok=False, error="login required"), 401
    data = request.get_json(silent=True) or {}
    to_user = data.get("to", "").strip()
    amount = data.get("amount", 0)

    if not to_user or not isinstance(amount, int) or amount <= 0:
        return jsonify(ok=False,
                       error="valid recipient and positive amount required"), 400
    if to_user == session["user"]:
        return jsonify(ok=False, error="cannot transfer to yourself"), 400

    sender = session["user"]
    conn = get_db()

    rcpt = conn.execute(
        "SELECT id FROM users WHERE username=?", (to_user,)).fetchone()
    if not rcpt:
        conn.close()
        return jsonify(ok=False, error="recipient not found"), 404

    # VULNERABLE: check balance in a separate read, then deduct later.
    # A real system would use SELECT ... FOR UPDATE inside a transaction.
    row = conn.execute(
        "SELECT balance FROM users WHERE username=?", (sender,)).fetchone()
    balance = row["balance"]

    if balance < amount:
        conn.close()
        return jsonify(ok=False,
                       error=f"insufficient funds (balance: {balance})"), 400

    # Simulate processing delay — fraud scoring, KYC/AML check, etc.
    time.sleep(0.2)

    conn.execute("UPDATE users SET balance = balance - ? WHERE username=?",
                 (amount, sender))
    conn.execute("UPDATE users SET balance = balance + ? WHERE username=?",
                 (amount, to_user))
    conn.execute(
        "INSERT INTO transactions (sender, receiver, amount, ts) "
        "VALUES (?,?,?,?)",
        (sender, to_user, amount, time.time()))
    conn.commit()

    new_bal = conn.execute(
        "SELECT balance FROM users WHERE username=?",
        (sender,)).fetchone()["balance"]
    conn.close()

    return jsonify(ok=True, balance=new_bal)


@app.route("/api/buy-premium", methods=["POST"])
def api_buy_premium():
    if "user" not in session:
        return jsonify(ok=False, error="login required"), 401

    conn = get_db()
    user = conn.execute("SELECT balance, premium FROM users WHERE username=?",
                        (session["user"],)).fetchone()

    if user["premium"]:
        conn.close()
        return jsonify(ok=False, error="already premium"), 400

    if user["balance"] < PREMIUM_COST:
        conn.close()
        return jsonify(
            ok=False,
            error=f"insufficient funds (need {PREMIUM_COST:,}, "
                  f"have {user['balance']:,})"), 400

    conn.execute(
        "UPDATE users SET balance = balance - ?, premium = 1 WHERE username=?",
        (PREMIUM_COST, session["user"]))
    conn.commit()
    conn.close()

    session["premium"] = True
    return jsonify(ok=True, message="Premium activated!")


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify(ok=False, error="username required"), 400

    conn = get_db()
    user = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user:
        return jsonify(ok=False, error="user not found"), 404

    ts = int(time.time())
    token = hashlib.md5(f"{username}{ts}".encode()).hexdigest()
    reset_tokens[username] = {"token": token, "ts": ts}

    return jsonify(
        ok=True,
        message=f"Password reset link sent to {username}'s registered email.",
        requested_at=ts
    )


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    password = data.get("password", "").strip()
    if not token or not password:
        return jsonify(ok=False,
                       error="token and new password required"), 400

    for username, info in list(reset_tokens.items()):
        if info["token"] == token:
            conn = get_db()
            conn.execute("UPDATE users SET password=? WHERE username=?",
                         (password, username))
            conn.commit()
            conn.close()
            del reset_tokens[username]
            return jsonify(ok=True,
                           message=f"Password for {username} has been reset.")

    return jsonify(ok=False, error="invalid or expired token"), 400


@app.route("/api/internal/diagnostics")
def api_diagnostics():
    token = request.headers.get("X-Diag-Token", "")
    if token != "mint-internal-2026":
        return jsonify(ok=False, error="unauthorized"), 403

    return jsonify(
        ok=True,
        flag=FLAG1,
        system="Mint Platform v2.3.1",
        build="d4e8f2a",
        services={
            "auth": {
                "status": "operational",
                "sessions": "flask-cookie"
            },
            "transfer_engine": {
                "status": "operational",
                "mode": "async",
                "warning": "balance check is non-atomic — concurrent requests "
                           "may bypass validation. Fix deferred to v2.4."
            },
            "reset_service": {
                "status": "active",
                "mode": "emergency",
                "note": "Simplified token generation in use."
            }
        },
        note="You found a diagnostics endpoint left in production. "
             "The transfer engine warning above is worth investigating."
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
