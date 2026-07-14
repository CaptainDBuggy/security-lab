"""
Relay — the public web app (the recon surface).

No web *vulnerability* here on purpose. The web layer's only sin is information
disclosure: a forgotten deploy env file under /backup/ that leaks the service
account's SSH password. UNLIKE Sentry, robots.txt does NOT point at it — robots
points at a dead end (/admin/), so you have to actually brute-force directories
to find /backup/. The real foothold is credential reuse over SSH.
"""
from flask import Flask, Response

app = Flask(__name__)

LANDING = """<!doctype html>
<html><head><title>Relay — Log Pipeline</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 18px;color:#101828;line-height:1.5}
 header{border-bottom:3px solid #4338ca;padding-bottom:10px;margin-bottom:24px}
 .tag{color:#4338ca;font-weight:600;letter-spacing:.5px;font-size:13px;text-transform:uppercase}
 .card{background:#f6f8fa;border:1px solid #e3e8ef;border-radius:10px;padding:18px 20px;margin:16px 0}
 footer{margin-top:36px;color:#667085;font-size:12px;border-top:1px solid #e3e8ef;padding-top:12px}
 code{background:#eef2f6;padding:1px 6px;border-radius:4px}
</style></head><body>
<header>
  <div class="tag">Relay</div>
  <h1>Every log, everywhere, in one pipeline.</h1>
</header>
<p>Relay ingests, normalizes, and forwards logs from your whole fleet to whatever
SIEM you already run. Drop-in collectors, back-pressure handling, and a health
probe on every node so you know the pipeline is alive.</p>
<div class="card">
  <h3>Node status</h3>
  <p>This collector node is <strong>healthy</strong>. Automated health checks run
  on a schedule; see the on-node probe for details.</p>
</div>
<div class="card">
  <h3>Operators</h3>
  <p>Deploys are handled by the shared <code>svc</code> automation account until
  we finish the migration to per-engineer keys.</p>
</div>
<footer>Relay &middot; collector node &middot; internal staging — do not expose publicly.</footer>
</body></html>
"""

# robots.txt is a RED HERRING here: it points at /admin/ (a dead end). The real
# leak (/backup/) is NOT listed — you must brute-force to find it.
ROBOTS = "User-agent: *\nDisallow: /admin/\n"

ADMIN = """<!doctype html>
<html><head><title>403 Forbidden</title></head><body>
<h1>403 Forbidden</h1>
<p>Admin console access is restricted to the ops VPN. Your IP is not on the
allowlist.</p>
</body></html>
"""

BACKUP_INDEX = """<!doctype html>
<html><head><title>Index of /backup/</title></head><body>
<h1>Index of /backup/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="deploy.env">deploy.env</a>                                2026-07-02 04:41      386
</pre>
<hr>
</body></html>
"""

DEPLOY_ENV = """# ------------------------------------------------------------
#  Relay deploy environment  --  INTERNAL  --  DO NOT PUBLISH
# ------------------------------------------------------------
# Left here after the last rollout. Clean up /backup/ before audit.

RECON_MARKER=FLAG{recon_brut3f0rc3d_l3ak3d_env}

# shared automation account used for deploys on this collector node:
RELAY_SSH_USER=svc
RELAY_SSH_PASS=R3lay-Svc-2026!
RELAY_SSH_PORT=22

# TODO(ops): kill password auth, rotate this, and get /backup/ off the vhost.
"""


@app.route("/")
def index():
    return LANDING


@app.route("/robots.txt")
def robots():
    return Response(ROBOTS, mimetype="text/plain")


@app.route("/admin/")
def admin():
    return Response(ADMIN, status=403)


@app.route("/backup/")
def backup_index():
    return BACKUP_INDEX


@app.route("/backup/deploy.env")
def deploy_env():
    return Response(DEPLOY_ENV, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
