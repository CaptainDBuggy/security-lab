"""
Reviewly — intermediate web CTF (Cross-Site Scripting, take two).

A product-review site. Same primitive as Postboard (XSS) but every flag lands in a
DIFFERENT injection *context*, so it's fresh reps rather than a reskin:

  1. Reflected XSS — ATTRIBUTE breakout -> /search reflects `q` inside a double-quoted
                     HTML attribute. A bare <script> won't do; you must break OUT of the
                     attribute first ("> ...). Report the link; the mod's non-httpOnly
                     cookie is stealable -> flag1.
  2. Stored XSS   — COMMENTS -> product reviews are rendered unescaped. The mod
                     auto-reviews them. Their session cookie is httpOnly (can't steal),
                     so ride it: fetch('/admin') in their browser -> flag2.
  3. DOM XSS      — document.write SINK -> /share writes location.hash into the page via
                     document.write(). Unlike innerHTML, document.write DOES run a
                     <script>. Execute and call reveal() -> flag3.

Rerun-friendly: comments are deletable (× on each), and POST /reset wipes everything
back to seed WITHOUT a container restart. See the "Lab controls" panel.

A real headless-Chromium moderator bot runs in-container and actually executes your
payloads — not a regex pretending. Own the delivery, the context, and the exfil.

NOTE(author): output-encoding every sink (auto-escape / textContent / never document.
write untrusted input) kills all three. That's the SOLUTION.md lesson.
"""
import os
import time
import threading
import secrets
from collections import deque
from markupsafe import escape
from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG1 = "FLAG{r3fl3ct3d_4ttr_br34k0ut}"   # non-httpOnly mod cookie, stolen via reflected XSS
FLAG2 = "FLAG{st0r3d_r3v13w_x55_r1d3s}"   # httpOnly session -> ride it with fetch('/admin')
FLAG3 = "FLAG{d0m_x55_d0cum3nt_wr1t3}"    # DOM sink, self-driven (see reveal())

# Unforgeable moderator session id — random per container, known ONLY to the bot.
ADMIN_SID = secrets.token_urlsafe(24)

_lock = threading.Lock()
COMMENTS = deque(maxlen=100)      # stored reviews: dicts {id, author, body}
REPORTS = deque()                 # queue of same-origin paths reported to the moderator
BEACONS = deque(maxlen=50)        # attacker's collector: (ts, value)
_next_id = [1]


def seed():
    """(Re)initialise state to a clean, known baseline."""
    with _lock:
        COMMENTS.clear()
        REPORTS.clear()
        BEACONS.clear()
        _next_id[0] = 1
        for author, body in [
            ("ava", "Battery lasts all weekend — genuinely impressed."),
            ("marco", "Decent, but the app is clunky. 3/5."),
        ]:
            COMMENTS.append({"id": _next_id[0], "author": author, "body": body})
            _next_id[0] += 1


seed()


# ---------------------------------------------------------------- shared layout ----
SHELL = """
<!doctype html><html><head><title>Reviewly</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:36px auto;padding:0 16px;color:#1b1b28}
 header{border-bottom:2px solid #6a2c70;padding-bottom:8px;margin-bottom:18px}
 .card{background:#faf7fb;border:1px solid #e5dbe8;border-radius:8px;padding:16px;margin:12px 0}
 .flag{background:#2a0f2e;color:#f3d6f7;padding:8px 10px;border-radius:6px;font-family:monospace}
 a{color:#6a2c70} input,textarea{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#6a2c70;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
 .btn.sm{padding:2px 8px;font-size:13px} .btn.warn{background:#a3324a}
 .err{color:#b00020} code{background:#eee;padding:1px 4px;border-radius:3px}
 .rev{border-left:3px solid #6a2c70;padding:6px 10px;margin:8px 0;background:#fff;display:flex;justify-content:space-between;gap:8px}
 .who{font-weight:bold;font-size:13px;color:#6a2c70} .muted{color:#666;font-size:13px}
 .ctrls{background:#f1ecf3;border:1px dashed #b79cbd}
 form.inline{display:inline;margin:0}
</style></head><body>
<header><h2>🛍️ Reviewly <span class="muted">honest product reviews</span></h2>
<nav><a href="/">home</a> &middot; <a href="/reviews">reviews</a> &middot;
<a href="/search">search</a> &middot; <a href="/report">report to mod</a> &middot;
<a href="/share">share</a> &middot; <a href="/collector">collector</a></nav></header>
{{ body|safe }}
</body></html>
"""


def page(body):
    # body inserted marked-safe (NOT auto-escaped) — that's the XSS surface. It is a
    # context value, never re-parsed as Jinja, so there is no SSTI here.
    return render_template_string(SHELL, body=body)


def lab_controls():
    return (
        '<div class="card ctrls"><b>🧪 Lab controls</b> '
        '<span class="muted">(rerun without restarting the container)</span><br>'
        '<form class="inline" method="post" action="/reset">'
        '<button class="btn sm warn">Reset lab (wipe + reseed)</button></form> '
        '<form class="inline" method="post" action="/collector/clear">'
        '<button class="btn sm">Clear collector</button></form> '
        '<form class="inline" method="post" action="/comments/clear">'
        '<button class="btn sm">Delete all comments</button></form></div>'
    )


@app.route("/")
def index():
    return page(
        '<div class="card"><h3>Welcome to Reviewly</h3>'
        "<p>Read and post product reviews, search them, or flag one for the moderator. "
        "The moderator reviews new comments and reported links regularly.</p>"
        '<p class="muted">Three flags, format <code>FLAG{...}</code>. One primitive — '
        "XSS — but each flag lives in a different injection context: an HTML "
        "attribute, a stored comment, and a client-side <code>document.write</code>."
        "</p></div>"
        '<div class="card"><b>Start here:</b> '
        '<a href="/reviews">the reviews</a> &middot; '
        '<a href="/search?q=battery">search “battery”</a> &middot; '
        '<a href="/share#ref=friend">the share widget</a></div>' + lab_controls()
    )


# ---------------------------------------------------------------- 1) reflected (attr) ----
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # --- VULN #1: q reflected INSIDE a double-quoted attribute value, unencoded.
    #     A bare <script> is inert here — you must break out of value="..." first. ---
    body = (
        '<div class="card"><h3>Search reviews</h3>'
        '<form method="get">'
        f'<input name="q" value="{q}" placeholder="e.g. battery">'
        '<button class="btn">Search</button></form>'
    )
    if q:
        hits = [c for c in list(COMMENTS) if q.lower() in c["body"].lower()]
        body += f'<p class="muted">{len(hits)} review(s) mention that.</p>'
        for c in hits:
            body += (f'<div class="rev"><span><span class="who">{escape(c["author"])}</span> '
                     f'{escape(c["body"])}</span></div>')
    return page(body + "</div>")


# ---------------------------------------------------------------- 2) stored (comments) ----
@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body_txt = request.form.get("body", "")
        with _lock:
            COMMENTS.append({"id": _next_id[0], "author": author, "body": body_txt})
            _next_id[0] += 1
        return redirect("/reviews")
    form = (
        '<div class="card"><h3>Leave a review</h3><form method="post">'
        '<label>Name</label><input name="author" value="anonymous">'
        '<label>Your review</label><textarea name="body" rows="3"></textarea>'
        '<button class="btn">Post review</button></form>'
        '<p class="muted">New reviews are checked by the moderator.</p></div>'
    )
    # --- VULN #2: author + body rendered unescaped -> stored XSS ---
    body = form + '<div class="card"><h3>Recent reviews</h3>'
    for c in reversed(list(COMMENTS)):
        body += (
            f'<div class="rev"><span><span class="who">{c["author"]}</span> '
            f'{c["body"]}</span>'
            # per-comment delete button (app-controlled id) so you can clean up + rerun
            f'<form class="inline" method="post" action="/comments/delete">'
            f'<input type="hidden" name="id" value="{c["id"]}">'
            f'<button class="btn sm warn" title="delete">×</button></form></div>'
        )
    if not COMMENTS:
        body += '<p class="muted">No reviews yet.</p>'
    body += "</div>"
    return page(body + lab_controls())


@app.route("/comments/delete", methods=["POST"])
def comment_delete():
    try:
        cid = int(request.form.get("id", ""))
    except ValueError:
        return redirect("/reviews")
    with _lock:
        keep = [c for c in COMMENTS if c["id"] != cid]
        COMMENTS.clear()
        COMMENTS.extend(keep)
    return redirect("/reviews")


@app.route("/comments/clear", methods=["POST"])
def comments_clear():
    with _lock:
        COMMENTS.clear()
    return redirect("/reviews")


# ------------------------------------------------------- moderator-only page ----
def _is_mod():
    return request.cookies.get("sid") == ADMIN_SID


@app.route("/admin")
def admin():
    if not _is_mod():
        return page('<div class="card err">403 — moderators only.</div>'), 403
    return page(
        '<div class="card"><h3>🛡️ Moderator dashboard</h3>'
        "<p>Restricted. Internal review token:</p>"
        f'<p class="flag">{FLAG2}</p>'
        '<p class="muted">The mod session cookie is httpOnly, but this page is still '
        "readable by any script running in the moderator's browser.</p></div>"
    )


# ---------------------------------------------------------------- report queue ----
@app.route("/report", methods=["GET", "POST"])
def report():
    msg = ""
    if request.method == "POST":
        path = request.form.get("url", "").strip()
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
        '<label>Path on this site (the mod opens it in their browser)</label>'
        '<input name="url" placeholder="/search?q=hello">'
        '<button class="btn">Report</button></form>'
        '<p class="muted">The moderator opens reported links while logged in.</p>'
        "</div>" + msg
    )


# ---------------------------------------------------------------- exfil sink ----
@app.route("/collect")
def collect():
    c = request.args.get("c", "")
    if c:
        with _lock:
            BEACONS.append((time.strftime("%H:%M:%S"), c))
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
            body += f'<div class="rev"><span><span class="who">{ts}</span> {escape(val)}</span></div>'
    else:
        body += '<p class="muted">Nothing collected yet. Land a payload that beacons here.</p>'
    return page(body + "</div>" + lab_controls())


@app.route("/collector/clear", methods=["POST"])
def collector_clear():
    with _lock:
        BEACONS.clear()
    return redirect("/collector")


# ---------------------------------------------------------------- reset ----
@app.route("/reset", methods=["POST"])
def reset():
    seed()
    return page('<div class="card">🧼 Lab reset to a clean slate — comments reseeded, '
                'reports and collector cleared.</div>'
                '<div class="card"><a href="/reviews">back to reviews</a></div>')


# ---------------------------------------------------------------- 3) DOM XSS ----
# reveal() returns flag3, XOR-obfuscated so the source doesn't hand it over. Sink is
# document.write() of the URL hash — note a <script> DOES run through document.write.
SHARE = """
<!doctype html><html><head><title>Reviewly · share</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:36px auto;padding:0 16px}
.card{background:#faf7fb;border:1px solid #e5dbe8;border-radius:8px;padding:16px}a{color:#6a2c70}</style>
</head><body>
<p><a href="/">&larr; back to Reviewly</a></p>
<div class="card"><h3>Share this product</h3><div id="out"></div>
<p style="color:#666;font-size:13px">Tag who sent you: add <code>#ref=YourName</code> to the URL.</p></div>
<script>
(function () {
  var ref = new URLSearchParams(location.hash.slice(1)).get('ref') || 'a friend';
  // --- VULN #3: attacker-controlled hash written to the page via document.write ---
  document.write('<p>Referred by: ' + ref + '</p>');
})();
function reveal() {
  var codes = [108,102,107,109,81,78,26,71,117,82,31,31,117,78,26,73,95,71,25,68,94,117,93,88,27,94,25,87];
  return codes.map(function (n) { return String.fromCharCode(n ^ 42); }).join('');
}
</script>
</body></html>
"""


@app.route("/share")
def share():
    return SHARE


# ---------------------------------------------------------------- moderator bot ----
def moderator_bot():
    """Real headless Chromium carrying the moderator's cookies. Reviews the comments
    (fires stored XSS) and drains the report queue (fires reflected XSS)."""
    from playwright.sync_api import sync_playwright

    base = "http://127.0.0.1:5000"
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
                    {"name": "sid", "value": ADMIN_SID, "url": base, "httpOnly": True},
                    {"name": "moderator_token", "value": FLAG1, "url": base, "httpOnly": False},
                ])
                pg = ctx.new_page()
                pg.on("dialog", lambda d: d.dismiss())

                pg.goto(base + "/reviews", wait_until="networkidle", timeout=8000)
                pg.wait_for_timeout(1500)

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
    app.run(host="0.0.0.0", port=5000, threaded=True)
