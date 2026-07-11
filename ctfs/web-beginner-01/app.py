"""
SecureVault - a deliberately vulnerable beginner web CTF.
Three flags, escalating difficulty. Happy hunting.
(No spoilers in this file's structure — reading the source is a legit skill,
 but try the black-box approach first.)
"""
from flask import Flask, request, session, redirect, make_response, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)  # signed session cookie — can't be forged by hand

DB = "/tmp/vault.db"

# --- flags (three stages) ---
FLAG_1 = "FLAG{r3c0n_r0b0ts_n3v3r_li3}"
FLAG_2 = "FLAG{c00k13s_ar3_cl13nt_s1d3}"
FLAG_3 = "FLAG{sql_1nj3ct10n_th3_cl4ss1c}"


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, note TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password, role, note) VALUES (?,?,?,?)",
        [
            ("guest", "guest", "user", "Welcome! This is your personal vault. Nothing secret here."),
            ("admin", "Sup3r_S3cr3t_Passw0rd_Nobody_Guesses_9f2c", "admin",
             "ADMIN PRIVATE NOTE: production flag is " + FLAG_3),
        ],
    )
    con.commit()
    con.close()


PAGE = """
<!doctype html>
<title>SecureVault</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;background:#0f1117;color:#e6e6e6}
 a{color:#7dd3fc} input{padding:6px;margin:4px 0;width:100%;box-sizing:border-box}
 .box{background:#1a1d27;padding:16px 20px;border-radius:10px;border:1px solid #2a2f3a}
 .flag{color:#4ade80;font-weight:bold} .err{color:#f87171}
 button{padding:8px 16px;background:#2563eb;color:#fff;border:0;border-radius:6px;cursor:pointer}
</style>
<div class="box">{{ body|safe }}</div>
"""


def page(body):
    return render_template_string(PAGE, body=body)


@app.route("/")
def index():
    # DEV: don't forget to lock down robots.txt before we go to prod -jenkins
    return page("""
      <h1>🔐 SecureVault</h1>
      <p>The password manager that definitely won't get hacked.</p>
      <p><a href="/login">Login</a></p>
      <!-- DEV TODO: crawlers are indexing our staging paths. tighten /robots.txt before launch -->
    """)


@app.route("/robots.txt")
def robots():
    resp = make_response("User-agent: *\nDisallow: /dev-notes\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/dev-notes")
def dev_notes():
    return page(f"""
      <h2>🛠️ Internal Dev Notes (staging)</h2>
      <ul>
        <li>Test account <code>guest / guest</code> is still enabled — remove before prod.</li>
        <li>Admin panel at <code>/admin</code> gates on the <code>role</code> cookie. Fix later.</li>
        <li>Login form still uses the old query builder. Nobody's had time to fix it.</li>
      </ul>
      <p class="flag">{FLAG_1}</p>
      <p><em>(Flag 1 of 3 — recon.)</em></p>
      <p><a href="/login">Login &raquo;</a></p>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("""
          <h2>Login</h2>
          <form method="post">
            <input name="username" placeholder="username" autofocus>
            <input name="password" type="password" placeholder="password">
            <button>Sign in</button>
          </form>
        """)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # NOTE: intentionally vulnerable — do NOT copy this into real code.
    con = sqlite3.connect(DB)
    cur = con.cursor()
    query = f"SELECT username, role FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cur.execute(query)
        row = cur.fetchone()
    except Exception as e:
        con.close()
        return page(f'<h2>Login</h2><p class="err">Query error: {e}</p><p><a href="/login">back</a></p>')
    con.close()

    if not row:
        return page('<h2>Login</h2><p class="err">Invalid credentials.</p><p><a href="/login">back</a></p>')

    session["user"] = row[0]
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("role", row[1])  # plain, unsigned cookie
    return resp


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect("/login")
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT note FROM users WHERE username=?", (user,))
    r = cur.fetchone()
    con.close()
    note = r[0] if r else "(no note)"
    return page(f"""
      <h2>Welcome, {user} 👋</h2>
      <p><strong>Your private note:</strong></p>
      <p>{note}</p>
      <p><a href="/admin">Admin panel</a> · <a href="/login">Log out</a></p>
    """)


@app.route("/admin")
def admin():
    role = request.cookies.get("role", "none")
    if role != "admin":
        return page(f"""
          <h2>⛔ Admin Panel</h2>
          <p class="err">Access denied. Your role is: <code>{role}</code></p>
          <p>Only administrators may view this page.</p>
        """)
    return page(f"""
      <h2>👑 Admin Panel</h2>
      <p>Welcome, administrator.</p>
      <p class="flag">{FLAG_2}</p>
      <p><em>(Flag 2 of 3 — client-side trust.)</em></p>
      <p>Still can't read the admin's private vault, though. That needs a real login.</p>
    """)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
