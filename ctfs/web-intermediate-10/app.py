"""
Postboard — intermediate web CTF (Cross-Site Scripting).

Deliberately vulnerable. One primitive — XSS — drilled in three escalating flavours
so it becomes automatic:

  1. Reflected XSS   -> /search reflects `q` straight into the HTML. Report a crafted
                        link to the moderator; their browser runs your JS. The mod's
                        `moderator_token` cookie is NOT httpOnly, so document.cookie
                        theft leaks flag1.
  2. Stored XSS      -> /board renders each note's author+message unescaped. The
                        moderator auto-reviews the board, so a stored payload fires in
                        their session. The `sid` cookie IS httpOnly (can't steal it) —
                        but you can still *ride* the session: fetch('/admin') with the
                        victim's cookie and exfiltrate flag2.
  3. DOM-based XSS   -> /widget writes location.hash into innerHTML client-side. No
                        server round-trip. Achieve execution in the page context and
                        call the guarded reveal() to print flag3.

A real headless-Chromium "moderator bot" runs in-container and actually executes your
payloads — this is not a regex that pretends. That's the point: own the delivery, the
context, and the exfil, not just an alert() box.

NOTE(author): output-encoding every sink (Jinja auto-escape / textContent instead of
innerHTML) kills all three. That's the SOLUTION.md lesson — never build HTML by pasting
untrusted input, on the server OR the client.
"""
import os
import time
import threading
import secrets
from collections import deque
from markupsafe import escape
from flask import Flask, request, session, redirect, make_response, render_template_string

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG1 = "FLAG{r3fl3ct3d_x55_c00k13_th13f}"     # non-httpOnly mod cookie, stolen via reflected XSS
FLAG2 = "FLAG{st0r3d_x55_r1d3s_th3_s3ss10n}"   # httpOnly session -> ride it with fetch('/admin')
FLAG3 = "FLAG{d0m_x55_1nn3rHTML_s1nk}"         # DOM sink, self-driven (see reveal())

# Unforgeable moderator session id — random per container, known ONLY to the bot.
# Guards /admin and /moderator/queue. A player can never mint this, so the only way
# into those pages is to ride the moderator's browser via XSS.
ADMIN_SID = secrets.token_urlsafe(24)

# In-memory state (resets on container restart — that IS the reset button).
_lock = threading.Lock()
NOTES = deque(maxlen=50)          # stored board notes: (author, message)
REPORTS = deque()                 # queue of same-origin paths reported to the moderator
BEACONS = deque(maxlen=50)        # attacker's collector: (ts, value) exfiltrated by your XSS

# Seed the board so /board is never empty.
NOTES.append(("librarian", "Welcome to Postboard! Keep it civil — the mod reviews new notes."))


# ---------------------------------------------------------------- shared layout ----
SHELL = """
<!doctype html><html><head><title>Postboard</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1a1a2e}
 header{border-bottom:2px solid #2d2d5a;padding-bottom:8px;margin-bottom:20px}
 .card{background:#f4f4fb;border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}
 .flag{background:#141433;color:#c5d0f7;padding:8px 10px;border-radius:6px;font-family:monospace}
 a{color:#3a3a8f} input,textarea{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#3a3a8f;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
 .err{color:#b00020} code{background:#eee;padding:1px 4px;border-radius:3px}
 .note{border-left:3px solid #3a3a8f;padding:6px 10px;margin:8px 0;background:#fff}
 .who{font-weight:bold;font-size:13px;color:#3a3a8f} .muted{color:#666;font-size:13px}
</style></head><body>
<header><h2>📌 Postboard <span class="muted">community notice board</span></h2>
<nav><a href="/">home</a> &middot; <a href="/board">board</a> &middot;
<a href="/search">search</a> &middot; <a href="/report">report to mod</a> &middot;
<a href="/widget">widget</a> &middot; <a href="/collector">collector</a></nav></header>
{{ body|safe }}
</body></html>
"""


def page(body):
    # body is inserted marked-safe (NOT auto-escaped) — that's the XSS surface.
    # It is passed as a context value, so it is never re-parsed as Jinja (no SSTI).
    return render_template_string(SHELL, body=body)


@app.route("/")
def index():
    return page(
        '<div class="card"><h3>Welcome to Postboard</h3>'
        "<p>Post a note to the board, search past notes, or flag something for the "
        "moderator to review. The moderator reviews new notes and reported links "
        "regularly.</p>"
        '<p class="muted">Three flags, format <code>FLAG{...}</code>. One primitive — '
        "cross-site scripting — in three flavours.</p></div>"
        '<div class="card"><b>Start here:</b> '
        '<a href="/board">the board</a> &middot; '
        '<a href="/search?q=hello">search “hello”</a> &middot; '
        '<a href="/widget#name=guest">the widget</a></div>'
    )


# ---------------------------------------------------------------- 1) reflected ----
@app.route("/search")
def search():
    q = request.args.get("q")
    form = (
        '<div class="card"><form method="get">'
        '<label>Search past notes</label>'
        f'<input name="q" value="{q or ""}" placeholder="e.g. welcome">'
        '<button class="btn">Search</button></form></div>'
    )
    if q is None:
        return page(form)
    # --- VULN #1: query reflected into the page with NO output encoding ---
    hits = [n for n in list(NOTES) if q.lower() in (n[0] + n[1]).lower()]
    body = form + f'<div class="card">You searched for: {q}<hr>'
    if hits:
        for who, msg in hits:
            body += f'<div class="note"><div class="who">{escape(who)}</div>{escape(msg)}</div>'
    else:
        body += '<p class="muted">No notes matched.</p>'
    body += "</div>"
    return page(body)


# ---------------------------------------------------------------- 2) stored ----
@app.route("/board", methods=["GET", "POST"])
def board():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        message = request.form.get("message", "")
        with _lock:
            NOTES.append((author, message))
        return redirect("/board")
    form = (
        '<div class="card"><h3>Post a note</h3><form method="post">'
        '<label>Name</label><input name="author" value="anonymous">'
        '<label>Message</label><textarea name="message" rows="3"></textarea>'
        '<button class="btn">Post</button></form>'
        '<p class="muted">New notes are reviewed by the moderator.</p></div>'
    )
    # --- VULN #2: each note's author + message rendered unescaped ---
    body = form + '<div class="card"><h3>Recent notes</h3>'
    for who, msg in reversed(list(NOTES)):
        body += f'<div class="note"><div class="who">{who}</div>{msg}</div>'
    body += "</div>"
    return page(body)


# ------------------------------------------------------- moderator-only pages ----
def _is_mod():
    return request.cookies.get("sid") == ADMIN_SID


@app.route("/admin")
def admin():
    # Only the moderator's browser can reach this — the sid cookie is unforgeable and
    # httpOnly. You get here by RIDING the mod's session from stored XSS, not by asking.
    if not _is_mod():
        return page('<div class="card err">403 — moderators only.</div>'), 403
    return page(
        '<div class="card"><h3>🛡️ Moderator dashboard</h3>'
        "<p>Restricted. Internal review token:</p>"
        f'<p class="flag">{FLAG2}</p>'
        '<p class="muted">Do not paste this anywhere. The mod session cookie is '
        "httpOnly, but this page is still readable by any script running in the "
        "moderator's browser.</p></div>"
    )


@app.route("/moderator/queue")
def mod_queue():
    if not _is_mod():
        return page('<div class="card err">403 — moderators only.</div>'), 403
    with _lock:
        items = list(REPORTS)
    body = '<div class="card"><h3>Reported links</h3>'
    body += "".join(f'<div class="note">{escape(p)}</div>' for p in items) or \
            '<p class="muted">Queue empty.</p>'
    return page(body + "</div>")


# ---------------------------------------------------------------- report queue ----
@app.route("/report", methods=["GET", "POST"])
def report():
    msg = ""
    if request.method == "POST":
        path = request.form.get("url", "").strip()
        # Same-origin paths only — the mod reviews links on THIS site.
        if path.startswith("/") and not path.startswith("//"):
            with _lock:
                REPORTS.append(path)
            msg = ('<div class="card">✅ Reported <code>' + escape(path) +
                   "</code>. The moderator will review it shortly.</div>")
        else:
            msg = ('<div class="card err">Only same-origin paths are accepted, '
                   "e.g. <code>/search?q=...</code></div>")
    return page(
        '<div class="card"><h3>Report a link to the moderator</h3>'
        '<form method="post">'
        '<label>Path on this site (the mod will open it in their browser)</label>'
        '<input name="url" placeholder="/search?q=hello">'
        '<button class="btn">Report</button></form>'
        '<p class="muted">The moderator opens reported links while logged in.</p>'
        "</div>" + msg
    )


# ---------------------------------------------------------------- exfil sink ----
@app.route("/collect")
def collect():
    # Your beacon target. Anything your XSS sends here shows up on /collector.
    c = request.args.get("c", "")
    if c:
        with _lock:
            BEACONS.append((time.strftime("%H:%M:%S"), c))
    # 1x1 gif so <img src=/collect?c=...> loads cleanly
    resp = make_response(
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
        b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )
    resp.headers["Content-Type"] = "image/gif"
    return resp


@app.route("/collector")
def collector():
    with _lock:
        rows = list(BEACONS)
    body = ('<div class="card"><h3>📡 Your collector</h3>'
            "<p>Data your XSS beacons have exfiltrated to <code>/collect?c=...</code>:</p>")
    if rows:
        for ts, val in reversed(rows):
            body += f'<div class="note"><div class="who">{ts}</div>{escape(val)}</div>'
    else:
        body += '<p class="muted">Nothing collected yet. Land a payload that beacons here.</p>'
    return page(body + "</div>")


# ---------------------------------------------------------------- 3) DOM XSS ----
# reveal() returns flag3, XOR-obfuscated so the source doesn't hand it over — the
# intended path is to achieve DOM execution and call it. Sink: hash -> innerHTML.
WIDGET = """
<!doctype html><html><head><title>Postboard widget</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
.card{background:#f4f4fb;border:1px solid #ddd;border-radius:8px;padding:16px}
a{color:#3a3a8f}</style></head><body>
<p><a href="/">&larr; back to Postboard</a></p>
<div class="card"><h3>Greeting widget</h3><div id="greeting">Hi, friend!</div>
<p style="color:#666;font-size:13px">Personalise me: add <code>#name=YourName</code> to the URL.</p></div>
<script>
(function () {
  var params = new URLSearchParams(location.hash.slice(1));
  var name = params.get('name') || 'friend';
  // --- VULN #3: attacker-controlled hash written to innerHTML (DOM sink) ---
  document.getElementById('greeting').innerHTML = 'Hi, ' + name + '!';
})();
function reveal() {
  var codes = [108,102,107,109,81,78,26,71,117,82,31,31,117,27,68,68,25,88,98,126,103,102,117,89,27,68,65,87];
  return codes.map(function (n) { return String.fromCharCode(n ^ 42); }).join('');
}
</script>
</body></html>
"""


@app.route("/widget")
def widget():
    return WIDGET


# ---------------------------------------------------------------- moderator bot ----
def moderator_bot():
    """Real headless Chromium carrying the moderator's cookies. It reviews the board
    (fires stored XSS) and drains the report queue (fires reflected XSS), executing
    whatever JS your payloads inject — same as a human mod clicking around."""
    from playwright.sync_api import sync_playwright

    base = "http://127.0.0.1:5000"
    # Wait for Flask to come up.
    for _ in range(30):
        try:
            import urllib.request
            urllib.request.urlopen(base, timeout=1)
            break
        except Exception:
            time.sleep(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        while True:
            try:
                ctx = browser.new_context()
                ctx.add_cookies([
                    # httpOnly session -> can't be stolen via document.cookie
                    {"name": "sid", "value": ADMIN_SID, "url": base, "httpOnly": True},
                    # sloppy non-httpOnly token -> flag1, stealable via document.cookie
                    {"name": "moderator_token", "value": FLAG1, "url": base, "httpOnly": False},
                ])
                pg = ctx.new_page()
                pg.on("dialog", lambda d: d.dismiss())  # don't hang on alert()

                # 1) Review the board -> stored XSS fires in mod session.
                pg.goto(base + "/board", wait_until="networkidle", timeout=8000)
                pg.wait_for_timeout(1500)

                # 2) Drain reported links -> reflected XSS fires in mod session.
                with _lock:
                    todo = list(REPORTS)
                    REPORTS.clear()
                for path in todo:
                    try:
                        pg.goto(base + path, wait_until="networkidle", timeout=8000)
                        pg.wait_for_timeout(1500)
                    except Exception:
                        pass

                ctx.close()
            except Exception:
                pass
            time.sleep(5)


if __name__ == "__main__":
    threading.Thread(target=moderator_bot, daemon=True).start()
    # threaded=True so the bot's page loads and your beacons don't serialise/deadlock.
    app.run(host="0.0.0.0", port=5000, threaded=True)
