"""
Loglet — intermediate web CTF (a CHAINED box).

An internal incident-log / alerting portal for an ops team. Three deliberately-planted
weaknesses wired end-to-end: each stage hands you exactly what the next one needs, so
there is no path to flag 3 that skips 1 -> 2. This is an attack *path*, not three
isolated puzzles.

  1. SQL Injection            -> /api/search builds a SQL string by concatenation. It's a
     (UNION extraction)          3-column query, so a UNION SELECT pulls the operators
                                 table — including admin's password — straight out. Log in
                                 as admin with the recovered creds.  (flag1, on /dashboard)

  2. Arbitrary File Read      -> the admin report viewer opens /report?file=<name> with no
     (LFI)                       containment. An absolute path (or ../) reads any file the
                                 app can — point it at the app's own config.ini to lift
                                 flag2 AND the maintenance token.  (flag2)

  3. OS Command Injection     -> /api/maintenance runs a shell command with your `target`
     (RCE)                       spliced in (shell=True). It's gated behind the maintenance
                                 token from step 2. Inject a second command to read the
                                 flag file off disk.  (flag3)

Discovery note (author): nothing is handed to you via robots.txt. The API endpoints and
their parameters live in the inline <script> on each page and in your Burp history — read
it like a real SPA bundle. That's the intended recon.

The fixes (see SOLUTION.md): use parameterised queries / bound params, never string-build
SQL (1); resolve the requested path and confirm it stays inside the reports dir, or serve
by opaque id (2); never pass user input to a shell — use argv arrays and validate the
target as an IP/host (3).
"""
import os
import sqlite3
import secrets
import subprocess

from flask import (Flask, request, session, redirect, jsonify,
                   render_template_string)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_PATH = "/tmp/loglet.db"
REPORTS_DIR = "/app/reports"
CONFIG_PATH = "/app/config.ini"

# ------------------------------------------------------------------ flags -----------
FLAG1 = "FLAG{un10n_sql1_dump3d_th3_0p3r4t0rs}"
FLAG2 = "FLAG{arb1tr4ry_f1l3_r34d_c0nf1g_l00t}"
FLAG3 = "FLAG{sh3ll_m3t4ch4r_c0mm4nd_1nj3ct10n}"

# A random maintenance token, minted per boot. You are NOT shown it — you lift it out of
# config.ini via the file-read bug (stage 2), and it gates the command endpoint (stage 3).
MAINT_TOKEN = secrets.token_hex(8)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def seed():
    conn = db()
    c = conn.cursor()
    c.executescript("""
        DROP TABLE IF EXISTS operators;
        DROP TABLE IF EXISTS incidents;
        CREATE TABLE operators (username TEXT, password TEXT, role TEXT);
        CREATE TABLE incidents (tag TEXT, ref TEXT, summary TEXT, severity TEXT);
    """)
    # admin's password is random per boot; the only way to it is the UNION injection.
    c.execute("INSERT INTO operators VALUES (?,?,?)",
              ("admin", secrets.token_hex(16), "admin"))
    c.execute("INSERT INTO operators VALUES (?,?,?)",
              ("j.reyes", secrets.token_hex(12), "operator"))
    c.execute("INSERT INTO operators VALUES (?,?,?)",
              ("t.okafor", secrets.token_hex(12), "operator"))
    c.executemany("INSERT INTO incidents VALUES (?,?,?,?)", [
        ("network", "INC-1041", "packet loss on core switch", "high"),
        ("network", "INC-1055", "BGP flap us-east", "medium"),
        ("auth",    "INC-1078", "brute-force against VPN", "high"),
        ("disk",    "INC-1090", "log volume 92% full", "low"),
    ])
    conn.commit()
    conn.close()


def write_config():
    # config.ini is NOT web-served; it's on disk for the app to read. The file-read bug is
    # what exposes it.
    with open(CONFIG_PATH, "w") as f:
        f.write("[loglet]\n")
        f.write("db_path = /tmp/loglet.db\n")
        f.write("report_dir = /app/reports\n")
        f.write(f"maintenance_token = {MAINT_TOKEN}\n")
        f.write(f"note = ops flag checkpoint -> {FLAG2}\n")


def current_user():
    return session.get("user")


def current_role():
    return session.get("role")


# ------------------------------------------------------------------ layout ----------
SHELL = """
<!doctype html><html><head><title>Loglet</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:800px;margin:34px auto;padding:0 16px;color:#10241f;background:#eef4f1}
 header{border-bottom:2px solid #047857;padding-bottom:8px;margin-bottom:18px}
 .card{background:#fff;border:1px solid #cfe0d8;border-radius:8px;padding:16px;margin:12px 0}
 a{color:#047857} input,textarea{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px;color:#3c5850}
 .btn{background:#047857;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .muted{color:#5a726a;font-size:13px} code{background:#e2ece7;padding:1px 4px;border-radius:3px}
 .flag{background:#053024;color:#6ee7b7;padding:10px;border-radius:6px;font-family:ui-monospace,monospace;word-break:break-all}
 pre{background:#10241f;color:#d1fae5;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
 table{width:100%;border-collapse:collapse;font-size:14px} th,td{border:1px solid #cfe0d8;padding:6px;text-align:left}
 nav a{margin-right:10px} .err{color:#b00020}
</style></head><body>
<header><h2>📟 Loglet <span class="muted">incident log &amp; alerting portal</span></h2>
<nav>{{ nav|safe }}</nav></header>
{{ body|safe }}
</body></html>
"""


def page(body, nav=""):
    return render_template_string(SHELL, body=body, nav=nav)


def nav_for():
    if not current_user():
        return '<a href="/">home</a> · <a href="/login">sign in</a>'
    links = '<a href="/dashboard">dashboard</a>'
    if current_role() == "admin":
        links += ' · <a href="/reports">reports</a> · <a href="/maintenance">maintenance</a>'
    links += ' · <a href="/logout">sign out</a>'
    return links


# ------------------------------------------------------------------ pages -----------
@app.route("/")
def index():
    body = """
    <div class="card">
      <h3>Incident search</h3>
      <p class="muted">Public tag lookup — search the incident log by tag
      (e.g. <code>network</code>, <code>auth</code>, <code>disk</code>).</p>
      <label>Tag</label><input id="q" placeholder="network">
      <p><button class="btn" onclick="search()">Search</button></p>
      <div id="out"></div>
    </div>
    <script>
    // Public search API. The server looks up incidents whose tag matches your query.
    async function search(){
      const r = await fetch('/api/search?q=' + encodeURIComponent(q.value));
      const j = await r.json();
      if(!j.ok){ out.innerHTML = '<p class="err">'+(j.error||'error')+'</p>'; return; }
      let h = '<table><tr><th>ref</th><th>summary</th><th>severity</th></tr>';
      for(const row of j.rows){ h += '<tr><td>'+row[0]+'</td><td>'+row[1]+'</td><td>'+row[2]+'</td></tr>'; }
      out.innerHTML = h + '</table>' + '<p class="muted">'+j.rows.length+' row(s)</p>';
    }
    </script>
    """
    return page(body, nav=nav_for())


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    # VULN #1 (SQL injection): the tag is concatenated straight into the SQL. The query
    # returns 3 columns (ref, summary, severity), so a UNION SELECT of 3 columns injects
    # arbitrary data — e.g. UNION SELECT username, password, role FROM operators.
    sql = "SELECT ref, summary, severity FROM incidents WHERE tag = '%s'" % q
    try:
        conn = db()
        rows = conn.execute(sql).fetchall()
        conn.close()
    except Exception as e:
        return jsonify(ok=False, error=f"query error: {e}")
    return jsonify(ok=True, rows=[list(r) for r in rows])


@app.route("/login")
def login_page():
    body = """
    <div class="card">
      <h3>Operator sign-in</h3>
      <p class="muted">Sign in with your operator credentials.</p>
      <label>Username</label><input id="u">
      <label>Password</label><input id="p" type="password">
      <p><button class="btn" onclick="login()">Sign in</button></p>
      <p id="msg" class="err"></p>
    </div>
    <script>
    async function login(){
      const r = await fetch('/api/login', {method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({username:u.value, password:p.value})});
      const j = await r.json();
      if(j.ok){ location='/dashboard'; } else { msg.textContent = j.error||'failed'; }
    }
    </script>
    """
    return page(body, nav=nav_for())


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u = data.get("username", "")
    p = data.get("password", "")
    # Parameterised on purpose — the login is NOT the injectable surface. You must recover
    # admin's password via the search injection (stage 1) and sign in for real here.
    conn = db()
    row = conn.execute("SELECT username, role FROM operators WHERE username=? AND password=?",
                       (u, p)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False, error="Invalid credentials")
    session["user"] = row["username"]
    session["role"] = row["role"]
    return jsonify(ok=True)


@app.route("/dashboard")
def dashboard():
    if not current_user():
        return redirect("/login")
    extra = ""
    if current_role() == "admin":
        extra = f"""
        <div class="card">
          <h3>Admin — you're in as <code>{current_user()}</code></h3>
          <p>Recovered the operator table and signed in as admin. Checkpoint one:</p>
          <div class="flag">{FLAG1}</div>
          <p class="muted">Admin tools unlocked: <a href="/reports">reports</a> ·
          <a href="/maintenance">maintenance</a>.</p>
        </div>"""
    body = f"""
    <div class="card">
      <h3>Welcome, {current_user()} <span class="muted">({current_role()})</span></h3>
      <p class="muted">Your incident dashboard.</p>
    </div>{extra}
    """
    return page(body, nav=nav_for())


@app.route("/reports")
def reports():
    if current_role() != "admin":
        return page('<div class="card"><h3 class="err">403 — admin only</h3></div>',
                    nav=nav_for()), 403
    body = """
    <div class="card">
      <h3>Report viewer</h3>
      <p class="muted">Open a saved incident report by file name from the report store.</p>
      <label>File</label><input id="f" placeholder="incident-1041.txt">
      <p><button class="btn" onclick="view()">Open</button></p>
      <pre id="out" style="display:none"></pre>
    </div>
    <script>
    async function view(){
      const r = await fetch('/report?file=' + encodeURIComponent(f.value));
      const t = await r.text();
      out.style.display='block'; out.textContent = t;
    }
    </script>
    """
    return page(body, nav=nav_for())


@app.route("/report")
def report():
    if current_role() != "admin":
        return "admin only", 403
    name = request.args.get("file", "")
    if not name:
        return "supply ?file=", 400
    # VULN #2 (arbitrary file read / LFI): the requested name is joined onto the reports
    # dir with no containment check. os.path.join drops the base entirely if `name` is
    # absolute, and `../` climbs out otherwise — so any readable file is fair game,
    # including the app's own config.ini.
    path = os.path.join(REPORTS_DIR, name)
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return f"cannot read: {e}", 404


@app.route("/maintenance")
def maintenance_page():
    if current_role() != "admin":
        return page('<div class="card"><h3 class="err">403 — admin only</h3></div>',
                    nav=nav_for()), 403
    body = """
    <div class="card">
      <h3>Connectivity check</h3>
      <p class="muted">Ping a host to verify reachability from the log collector. Requires
      the maintenance token (see the service config).</p>
      <label>Maintenance token</label><input id="tok" placeholder="token">
      <label>Target host</label><input id="t" placeholder="10.0.0.1">
      <p><button class="btn" onclick="run()">Run check</button></p>
      <pre id="out" style="display:none"></pre>
    </div>
    <script>
    async function run(){
      const r = await fetch('/api/maintenance', {method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({token:tok.value, target:t.value})});
      const j = await r.json();
      out.style.display='block';
      out.textContent = j.ok ? j.output : (j.error||'error');
    }
    </script>
    """
    return page(body, nav=nav_for())


@app.route("/api/maintenance", methods=["POST"])
def api_maintenance():
    if current_role() != "admin":
        return jsonify(ok=False, error="admin only"), 403
    data = request.get_json(silent=True) or {}
    if data.get("token") != MAINT_TOKEN:
        return jsonify(ok=False, error="bad maintenance token"), 403
    target = data.get("target", "")
    # VULN #3 (OS command injection): `target` is spliced into a shell command run with
    # shell=True. A shell metacharacter (`;`, `|`, `$()`, `&&`) breaks out and runs an
    # arbitrary command — e.g. `127.0.0.1; cat /flag3.txt`.
    cmd = f"ping -c 1 -W 1 {target}"
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return jsonify(ok=True, output=(out.stdout + out.stderr))
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


def bootstrap():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    for tag, ref in [("network", "1041"), ("auth", "1078")]:
        with open(os.path.join(REPORTS_DIR, f"incident-{ref}.txt"), "w") as f:
            f.write(f"Incident {ref} ({tag}497)\n--------\nStatus: closed\nOwner: ops\n")
    write_config()
    seed()


if __name__ == "__main__":
    bootstrap()
    app.run(host="0.0.0.0", port=5000)
