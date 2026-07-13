"""
Sentry — the public web app (the recon surface).

There is no web *vulnerability* here on purpose. The web layer's only sin is
information disclosure: a forgotten backups directory (disallowed in robots.txt
but still served) that leaks a developer's SSH credentials. The real foothold is
credential reuse over SSH; the web app just hands you the key.
"""
from flask import Flask, Response

app = Flask(__name__)

LANDING = """<!doctype html>
<html><head><title>Sentry Security</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 18px;color:#101828;line-height:1.5}
 header{border-bottom:3px solid #0f766e;padding-bottom:10px;margin-bottom:24px}
 .tag{color:#0f766e;font-weight:600;letter-spacing:.5px;font-size:13px;text-transform:uppercase}
 .card{background:#f6f8fa;border:1px solid #e3e8ef;border-radius:10px;padding:18px 20px;margin:16px 0}
 footer{margin-top:36px;color:#667085;font-size:12px;border-top:1px solid #e3e8ef;padding-top:12px}
 code{background:#eef2f6;padding:1px 6px;border-radius:4px}
</style></head><body>
<header>
  <div class="tag">Sentry Security</div>
  <h1>Perimeter monitoring that never blinks.</h1>
</header>
<p>Sentry watches your edge so your team can sleep. Real-time alerting, log
retention, and 24/7 SOC coverage for teams that can't afford a bad night.</p>
<div class="card">
  <h3>Status</h3>
  <p>All production services operational. This host also runs our internal
  staging + deploy tooling — <em>authorized personnel only</em>.</p>
</div>
<div class="card">
  <h3>Contact</h3>
  <p>ops@sentry.example &middot; on-call rotation via the internal dashboard.</p>
</div>
<footer>Sentry Security &middot; staging node &middot; do not expose to the public internet.</footer>
</body></html>
"""

ROBOTS = "User-agent: *\nDisallow: /backups/\n"

BACKUPS_INDEX = """<!doctype html>
<html><head><title>Index of /backups/</title></head><body>
<h1>Index of /backups/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="dev_credentials.txt">dev_credentials.txt</a>                        2026-06-30 02:14      412
</pre>
<hr>
</body></html>
"""

CREDS = """# ============================================================
#  Sentry deploy notes  --  INTERNAL  --  DO NOT COMMIT / PUBLISH
# ============================================================
# Reminder from the last sprint: we still ship with a shared dev
# account until per-engineer SSH keys are rolled out. Rotate this
# BEFORE the next audit.

recon_marker: FLAG{recon_expos3d_backup_cr3ds}

# temporary shell access to this staging node:
ssh dev@<this-host>            # port 22
dev:Sup3rD3vPass!2026

# TODO(ops): disable password auth, enforce keys, and for the love of
# everything take /backups/ off the public vhost.
"""


@app.route("/")
def index():
    return LANDING


@app.route("/robots.txt")
def robots():
    return Response(ROBOTS, mimetype="text/plain")


@app.route("/backups/")
def backups_index():
    return BACKUPS_INDEX


@app.route("/backups/dev_credentials.txt")
def creds():
    return Response(CREDS, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
