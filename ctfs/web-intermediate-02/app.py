"""
OrgHub — intermediate web CTF (Broken Access Control).

Deliberately vulnerable. Three intended bugs, each a different flavour of broken
access control:

  1. IDOR (horizontal)               -> /account?id=<n> has no owner check
  2. Broken function-level authz     -> /admin/users has no role check (forced browsing)
  3. Mass assignment (vertical)      -> /account/update binds any POST field, incl. role

SQL is parameterised on purpose: the lesson here is authorization, not injection.
Sessions are signed with a random secret, so the client cannot forge role/identity —
escalation must go through the real bugs, not cookie tampering.
"""
import os
import sqlite3
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = os.urandom(32)  # random per boot -> sessions can't be forged offline

DB = "/tmp/orghub.db"
# The columns /account/update is *supposed* to touch is just full_name. It doesn't
# enforce that — that's the mass-assignment bug.
UPDATABLE = {"username", "password", "role", "full_name", "private_note"}


def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = get_db()
    con.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username     TEXT,
            password     TEXT,
            role         TEXT,
            full_name    TEXT,
            private_note TEXT
        );
        """
    )
    admin_pw = os.urandom(16).hex()  # unknown to the player: you must escalate, not log in
    users = [
        (1, "alice", "Password1!", "user", "Alice Adams",
         "Welcome to OrgHub! Tip: you can edit your display name from your dashboard."),
        (2, "bob", "hunter2-bob", "user", "Bob Barker",
         "Backup recovery code (keep private): FLAG{1d0r_0bj3ct_l3v3l_pwn3d}"),
        (3, "admin", admin_pw, "admin", "System Administrator",
         "Staff management console lives at /admin/users. TODO: actually lock it down."),
    ]
    con.executemany(
        "INSERT INTO users (id, username, password, role, full_name, private_note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        users,
    )
    con.commit()
    con.close()


PAGE = """
<!doctype html><html><head><title>OrgHub</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 16px;color:#1a1a2e}
 header{border-bottom:2px solid #16213e;padding-bottom:8px;margin-bottom:20px}
 .card{background:#f4f4f8;border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}
 .role{display:inline-block;background:#16213e;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}
 a{color:#0f3460} input{padding:6px;margin:4px 0} label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#0f3460;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
 .err{color:#b00020} code{background:#eee;padding:1px 4px;border-radius:3px}
</style></head><body>
<header><h2>🏢 OrgHub <span style="font-size:13px;color:#666">staff portal</span></h2></header>
{{ body|safe }}
</body></html>
"""


def render(body, **kw):
    return render_template_string(PAGE, body=render_template_string(body, **kw))


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    con.close()
    return row


@app.route("/robots.txt")
def robots():
    # Recon breadcrumb — reinforces the habit from CTF 01.
    return "User-agent: *\nDisallow: /admin\n", 200, {"Content-Type": "text/plain"}


@app.route("/")
def index():
    if session.get("uid"):
        return redirect("/dashboard")
    return render(
        """
        <div class="card">
          <h3>Sign in</h3>
          {% if error %}<p class="err">{{ error }}</p>{% endif %}
          <form method="post" action="/login">
            <label>Username <input name="username" value="alice"></label>
            <label>Password <input name="password" type="password"></label>
            <button class="btn">Log in</button>
          </form>
          <p style="font-size:13px;color:#666">Demo account: <code>alice</code> / <code>Password1!</code></p>
        </div>
        """,
        error=request.args.get("error"),
    )


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = get_db()
    row = con.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (u, p)
    ).fetchone()
    con.close()
    if not row:
        return redirect("/?error=Invalid+credentials")
    session["uid"] = row["id"]
    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
def dashboard():
    me = current_user()
    if not me:
        return redirect("/")
    return render(
        """
        <div class="card">
          <h3>Welcome, {{ me['full_name'] }} <span class="role">{{ me['role'] }}</span></h3>
          <p>Your account page: <a href="/account?id={{ me['id'] }}">/account?id={{ me['id'] }}</a></p>
        </div>
        <div class="card">
          <h4>Edit profile</h4>
          <form method="post" action="/account/update">
            <label>Display name <input name="full_name" value="{{ me['full_name'] }}"></label>
            <button class="btn">Save</button>
          </form>
        </div>
        <p><a href="/logout">Log out</a></p>
        """,
        me=me,
    )


@app.route("/account")
def account():
    if not session.get("uid"):
        return redirect("/")
    # BUG 1 (IDOR): serves whatever id is asked for, with no check that it belongs
    # to the logged-in user.
    target = request.args.get("id", "")
    con = get_db()
    row = con.execute("SELECT * FROM users WHERE id = ?", (target,)).fetchone()
    con.close()
    if not row:
        return render('<div class="card"><p class="err">No such account.</p></div>'), 404
    return render(
        """
        <div class="card">
          <h3>Account #{{ u['id'] }} — {{ u['full_name'] }} <span class="role">{{ u['role'] }}</span></h3>
          <p><b>Username:</b> {{ u['username'] }}</p>
          <p><b>Private note:</b> {{ u['private_note'] }}</p>
        </div>
        <p><a href="/dashboard">&larr; Back to dashboard</a></p>
        """,
        u=row,
    )


@app.route("/account/update", methods=["POST"])
def account_update():
    me = current_user()
    if not me:
        return redirect("/")
    # BUG 3 (mass assignment): blindly writes every submitted field that matches a
    # column, instead of whitelisting {full_name}. Sending role=admin promotes you.
    updates = {k: v for k, v in request.form.items() if k in UPDATABLE and k != "id"}
    if updates:
        sets = ", ".join(f"{k} = ?" for k in updates)
        con = get_db()
        con.execute(f"UPDATE users SET {sets} WHERE id = ?", (*updates.values(), me["id"]))
        con.commit()
        con.close()
    return redirect("/dashboard")


@app.route("/admin")
def admin():
    me = current_user()
    if not me:
        return redirect("/")
    # Function-level check IS present here — role read fresh from the DB, so a forged
    # cookie won't help. Legit admins (or anyone who escalated via BUG 3) get the flag.
    if me["role"] != "admin":
        return render(
            '<div class="card"><p class="err">Access denied.</p>'
            '<p>Your role is: <span class="role">{{ r }}</span></p></div>',
            r=me["role"],
        ), 403
    return render(
        """
        <div class="card">
          <h3>🔑 Admin console</h3>
          <p>Master key: <b>FLAG{m4ss_4ss1gnm3nt_r0l3_pwn}</b></p>
          <p>Staff list: <a href="/admin/users">/admin/users</a></p>
        </div>
        """
    )


@app.route("/admin/users")
def admin_users():
    # BUG 2 (broken function-level authz / forced browsing): this admin subpage has
    # NO role check at all — any logged-in user who finds the URL can read it.
    if not session.get("uid"):
        return redirect("/")
    con = get_db()
    rows = con.execute("SELECT id, username, role, full_name FROM users").fetchall()
    con.close()
    return render(
        """
        <div class="card">
          <h3>Staff directory</h3>
          <table>
            <tr><th>ID</th><th>Username</th><th>Role</th><th>Name</th></tr>
            {% for u in rows %}
            <tr><td>{{ u['id'] }}</td><td>{{ u['username'] }}</td>
                <td>{{ u['role'] }}</td><td>{{ u['full_name'] }}</td></tr>
            {% endfor %}
          </table>
          <p style="margin-top:14px;font-size:13px;color:#666">
            AUDIT TOKEN: FLAG{f0rc3d_br0ws1ng_h1dd3n_n0t_saf3}</p>
        </div>
        """,
        rows=rows,
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
