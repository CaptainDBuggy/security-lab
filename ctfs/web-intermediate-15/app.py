"""
Mailroom — intermediate web CTF (a CHAINED box).

Four deliberately-planted web vulnerabilities, wired end-to-end so each one is the key
that unlocks the next. There is no way to reach flag N without having used the bug that
gives you flag N-1 — this is an attack *path*, not four isolated puzzles.

  1. NoSQL Injection        -> /api/login builds a Mongo query straight from the JSON body
     (auth bypass)             ({"username": u, "password": p}). You have no credentials,
                               so you inject query operators ($ne / $gt / $regex) to make
                               the match succeed and get a session.  (flag1, on /dashboard)

  2. Mass Assignment        -> /api/profile "update your display name" blindly $set's the
     (privilege escalation)    ENTIRE JSON body onto your user document. Smuggle an extra
                               field ("role":"staff") and you promote yourself into the
                               staff area.  (flag2, on /staff)

  3. Insecure File Upload   -> the staff area's uploader claims "images only" but performs
     (no content check)        NO server-side validation. Upload something that isn't an
                               image at all and the server stores and serves it.  (flag3)

  4. Path Traversal / LFI   -> staff attachments are served by /attachments?name=<f>, which
     (arbitrary file read)     concatenates your name onto the upload dir with no
                               sanitising. `name=../private/flag4.txt` (or ../../etc/passwd)
                               escapes the folder and reads any file the app can.  (flag4)

Discovery note (author): nothing is handed to you via robots.txt. The JSON API endpoints
and their field names live in the inline <script> blocks on each page — read the HTML/JS
the way you'd read a real SPA's bundle. That's the intended recon.

The fixes (see SOLUTION.md): parameterise/coerce query values to strings and reject
operator objects (1); allow-list which fields a profile update may set (2); validate
upload content by magic bytes AND store outside the web root with a generated name (3);
resolve the requested path and confirm it stays inside the uploads dir before opening (4).
"""
import os
import secrets

import mongomock
from flask import (Flask, request, session, redirect, jsonify,
                   render_template_string, Response)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

UPLOAD_DIR = "/app/uploads"
PRIVATE_DIR = "/app/private"

# ------------------------------------------------------------------ "database" ------
# mongomock stands in for a real MongoDB server. The vulnerable code below is written
# exactly as it would be against pymongo — `users.find_one(query)` / `users.update_one(...)`
# — so the NoSQL-injection and mass-assignment lessons are faithful.
_client = mongomock.MongoClient()
users = _client.mailroom.users


def seed():
    users.delete_many({})
    # Real, unguessable passwords. You are NOT given them — the only way in is injection.
    users.insert_many([
        {"username": "alice",  "password": secrets.token_hex(24),
         "displayName": "Alice Nguyen", "role": "user",
         "desk": "3F-12"},
        {"username": "mailadmin", "password": secrets.token_hex(24),
         "displayName": "Mailroom Admin", "role": "admin",
         "desk": "1F-01"},
    ])


# ------------------------------------------------------------------ flags -----------
FLAG1 = "FLAG{n0sql_0p3r4t0r_1nj3ct10n_byp4ss}"
FLAG2 = "FLAG{m4ss_4ss1gnm3nt_s3lf_pr0m0t3d}"
FLAG3 = "FLAG{upl04d_n0_c0nt3nt_ch3ck_pwn3d}"
FLAG4 = "FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}"


def current_user():
    if "user" not in session:
        return None
    return users.find_one({"username": session["user"]})


# ------------------------------------------------------------------ layout ----------
SHELL = """
<!doctype html><html><head><title>Mailroom</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:36px auto;padding:0 16px;color:#0f2733;background:#f4f8fa}
 header{border-bottom:2px solid #0e7490;padding-bottom:8px;margin-bottom:18px}
 .card{background:#fff;border:1px solid #d5e3e8;border-radius:8px;padding:16px;margin:12px 0}
 a{color:#0e7490} input,textarea{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px;color:#3a5763}
 .btn{background:#0e7490;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .muted{color:#5c7683;font-size:13px} code{background:#e4eef2;padding:1px 4px;border-radius:3px}
 .flag{background:#052e2b;color:#5eead4;padding:10px;border-radius:6px;font-family:ui-monospace,monospace;word-break:break-all}
 pre{background:#0f2733;color:#dbeafe;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
 nav a{margin-right:10px} .err{color:#b00020}
</style></head><body>
<header><h2>📬 Mailroom <span class="muted">internal parcel &amp; document portal</span></h2>
<nav>{{ nav|safe }}</nav></header>
{{ body|safe }}
</body></html>
"""


def page(body, nav=""):
    return render_template_string(SHELL, body=body, nav=nav)


def nav_for(u):
    if not u:
        return '<a href="/">sign in</a>'
    links = '<a href="/dashboard">dashboard</a>'
    if u.get("role") in ("staff", "admin"):
        links += ' · <a href="/staff">staff area</a>'
    links += ' · <a href="/logout">sign out</a>'
    return links


# ------------------------------------------------------------------ pages -----------
@app.route("/")
def index():
    if current_user():
        return redirect("/dashboard")
    body = """
    <div class="card">
      <h3>Sign in</h3>
      <p class="muted">Mailroom accounts are provisioned by IT — no self-signup. If you
      can't remember your password, <b>contact IT</b>.</p>
      <label>Username</label><input id="u" placeholder="username">
      <label>Password</label><input id="p" type="password" placeholder="password">
      <p><button class="btn" onclick="login()">Sign in</button></p>
      <p id="msg" class="err"></p>
    </div>
    <script>
    // Auth is a JSON API. The server matches your creds against the users collection.
    async function login(){
      const r = await fetch('/api/login', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ username: u.value, password: p.value })
      });
      const j = await r.json();
      if(j.ok){ location = j.redirect; } else { msg.textContent = j.error || 'Sign-in failed'; }
    }
    </script>
    """
    return page(body, nav=nav_for(None))


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    # VULN #1 (NoSQL injection): username/password come straight from the JSON body and
    # are dropped into the query object unmodified. A caller who sends an OBJECT instead
    # of a string — e.g. {"$ne": ""} — injects a Mongo query operator and bypasses auth.
    query = {"username": username, "password": password}
    try:
        user = users.find_one(query)
    except Exception as e:
        return jsonify(ok=False, error=f"query error: {e}"), 400
    if not user:
        return jsonify(ok=False, error="Invalid credentials"), 401
    session["user"] = user["username"]
    return jsonify(ok=True, redirect="/dashboard")


@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect("/")
    staff_link = ('<p class="muted">You have staff access → '
                  '<a href="/staff">open the staff area</a>.</p>'
                  if u.get("role") in ("staff", "admin") else
                  '<p class="muted">Your role is <code>%s</code>. The staff sorting area '
                  'is restricted.</p>' % u.get("role"))
    body = f"""
    <div class="card">
      <h3>Welcome back, {u.get('displayName','?')} <span class="muted">({u['username']})</span></h3>
      <p>You're signed in. 🎉 First checkpoint:</p>
      <div class="flag">{FLAG1}</div>
      {staff_link}
    </div>
    <div class="card">
      <h3>Profile</h3>
      <p class="muted">Update your display name. Changes are saved to your account record.</p>
      <label>Display name</label><input id="dn" value="{u.get('displayName','')}">
      <p><button class="btn" onclick="save()">Save profile</button></p>
      <p id="pm" class="muted"></p>
    </div>
    <script>
    // Profile updates POST a JSON patch of your account. The server applies it to your
    // user document.
    async function save(){{
      const r = await fetch('/api/profile', {{
        method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{ displayName: dn.value }})
      }});
      const j = await r.json();
      pm.textContent = j.ok ? ('Saved. role=' + j.role) : (j.error||'error');
    }}
    </script>
    """
    return page(body, nav=nav_for(u))


@app.route("/api/profile", methods=["POST"])
def api_profile():
    u = current_user()
    if not u:
        return jsonify(ok=False, error="not signed in"), 401
    patch = request.get_json(silent=True) or {}
    # VULN #2 (mass assignment): the ENTIRE client patch is $set onto the user document.
    # The UI only sends displayName, but nothing stops a caller adding "role":"staff"
    # (or "admin") and promoting themselves.
    patch.pop("_id", None)          # only so a resent doc doesn't crash the update
    patch.pop("username", None)     # don't let them rename onto another account
    users.update_one({"username": u["username"]}, {"$set": patch})
    fresh = users.find_one({"username": u["username"]})
    return jsonify(ok=True, role=fresh.get("role"))


@app.route("/staff")
def staff():
    u = current_user()
    if not u:
        return redirect("/")
    if u.get("role") not in ("staff", "admin"):
        return page('<div class="card"><h3 class="err">403 — staff only</h3>'
                    '<p class="muted">Your role does not grant access to the sorting '
                    'area.</p></div>', nav=nav_for(u)), 403
    body = f"""
    <div class="card">
      <h3>🗂️ Staff sorting area</h3>
      <p>Role check passed — you're staff now.</p>
      <div class="flag">{FLAG2}</div>
    </div>
    <div class="card">
      <h3>Upload a parcel label</h3>
      <p class="muted">📎 Images only (JPG/PNG). Labels are attached to the parcel record.</p>
      <input type="file" id="f">
      <p><button class="btn" onclick="up()">Upload</button></p>
      <p id="um" class="muted"></p>
    </div>
    <div class="card">
      <h3>View an attachment</h3>
      <p class="muted">Attachments are served by name from the label store.</p>
      <label>File name</label><input id="an" placeholder="e.g. label.png">
      <p><button class="btn" onclick="view()">Open</button></p>
      <pre id="av" style="display:none"></pre>
    </div>
    <script>
    async function up(){{
      if(!f.files[0]){{ um.textContent='pick a file'; return; }}
      const fd = new FormData(); fd.append('file', f.files[0]);
      const r = await fetch('/api/upload', {{ method:'POST', body: fd }});
      const j = await r.json();
      um.innerHTML = j.ok
        ? ('Stored. View it at <code>/attachments?name=' + j.name + '</code>' +
           (j.flag ? ('<br><span class="flag">'+j.flag+'</span>') : ''))
        : (j.error||'error');
    }}
    async function view(){{
      const r = await fetch('/attachments?name=' + encodeURIComponent(an.value));
      const t = await r.text();
      av.style.display='block'; av.textContent = t;
    }}
    </script>
    """
    return page(body, nav=nav_for(u))


IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a")


@app.route("/api/upload", methods=["POST"])
def api_upload():
    u = current_user()
    if not u or u.get("role") not in ("staff", "admin"):
        return jsonify(ok=False, error="staff only"), 403
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(ok=False, error="no file"), 400
    # VULN #3 (insecure upload): the UI says "images only", but the server does NO content
    # validation. It trusts the client-supplied filename and stores whatever bytes arrive.
    name = os.path.basename(f.filename)          # (token gesture; content is unchecked)
    data = f.read()
    with open(os.path.join(UPLOAD_DIR, name), "wb") as out:
        out.write(data)
    is_image = any(data.startswith(m) for m in IMAGE_MAGIC)
    # Award the flag only when you prove the "images only" claim is a lie: a non-image got
    # through untouched.
    flag = None if is_image else FLAG3
    return jsonify(ok=True, name=name, flag=flag)


@app.route("/attachments")
def attachments():
    u = current_user()
    if not u or u.get("role") not in ("staff", "admin"):
        return jsonify(ok=False, error="staff only"), 403
    name = request.args.get("name", "")
    if not name:
        return "supply ?name=", 400
    # VULN #4 (path traversal / arbitrary read): the requested name is concatenated onto
    # the upload dir with no normalisation or containment check, so `../` climbs out and
    # reads any file the process can — e.g. ../private/flag4.txt or ../../etc/passwd.
    path = UPLOAD_DIR + "/" + name
    try:
        with open(path, "rb") as fh:
            body = fh.read()
    except Exception as e:
        return f"cannot read: {e}", 404
    return Response(body, mimetype="application/octet-stream")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    with open(os.path.join(PRIVATE_DIR, "flag4.txt"), "w") as fh:
        fh.write(FLAG4 + "\n")
    seed()
    app.run(host="0.0.0.0", port=5000)
