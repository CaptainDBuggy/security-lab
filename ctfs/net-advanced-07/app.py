"""
Forge — internal build / deploy dashboard (the RCE surface).

The vulnerability is a textbook OS command injection in the "connectivity check"
diagnostic: it interpolates a user-supplied host straight into a shell command
(`ping -c 1 <host>`) with shell=True and no sanitization. Inject `;`/`|`/`$()`
to run arbitrary commands as the web user (www-data). That is the foothold.

The app runs as the low-priv www-data user (see entrypoint), so RCE here is NOT
root — you land as www-data and must work your way up.
"""
from flask import Flask, request, Response
import subprocess

app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><title>Forge — Build Console</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:760px;margin:44px auto;padding:0 18px;color:#101828;line-height:1.5}}
 header{{border-bottom:3px solid #b45309;padding-bottom:10px;margin-bottom:22px}}
 .tag{{color:#b45309;font-weight:600;letter-spacing:.5px;font-size:13px;text-transform:uppercase}}
 .card{{background:#f6f8fa;border:1px solid #e3e8ef;border-radius:10px;padding:18px 20px;margin:16px 0}}
 input[type=text]{{width:60%;padding:8px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px}}
 button{{padding:8px 16px;border:0;border-radius:6px;background:#b45309;color:#fff;font-weight:600;cursor:pointer}}
 pre{{background:#0b1220;color:#d7e3f4;padding:14px;border-radius:8px;overflow:auto;font-size:13px}}
 footer{{margin-top:32px;color:#667085;font-size:12px;border-top:1px solid #e3e8ef;padding-top:12px}}
</style></head><body>
<header>
  <div class="tag">Forge</div>
  <h1>Build &amp; deploy console</h1>
</header>
<p>Internal CI dashboard for the Forge fleet. Trigger builds, ship releases, and
run node diagnostics. <em>Authorized engineers only.</em></p>
<div class="card">
  <h3>Node connectivity check</h3>
  <p>Verify this build node can reach a host before we schedule a deploy to it.</p>
  <form method="POST" action="/diagnostics">
    <input type="text" name="host" placeholder="e.g. 127.0.0.1" value="{host}">
    <button type="submit">Check</button>
  </form>
  {result}
</div>
<footer>Forge CI &middot; build node &middot; internal network only.</footer>
</body></html>
"""


@app.route("/", methods=["GET"])
def index():
    return PAGE.format(host="", result="")


@app.route("/diagnostics", methods=["POST"])
def diagnostics():
    host = request.form.get("host", "")
    # --- VULNERABILITY: unsanitized user input in a shell command ---
    try:
        proc = subprocess.run(
            f"ping -c 1 {host}",
            shell=True, capture_output=True, text=True, timeout=15,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        output = "diagnostic timed out."
    result = "<pre>{}</pre>".format(
        output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        or "(no output)"
    )
    # reflect host back un-escaped-for-value only (cosmetic); the sink above is the bug
    safe_host = host.replace('"', "&quot;")
    return PAGE.format(host=safe_host, result=result)


if __name__ == "__main__":
    # Non-root user cannot bind :80, so the app listens high; compose maps 8084->8000.
    app.run(host="0.0.0.0", port=8000)
