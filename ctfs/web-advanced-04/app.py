"""
LinkPeek — advanced web CTF (Server-Side Request Forgery).

A "link preview" service: you hand it a URL, the SERVER fetches that URL and
shows you a preview of what came back. That server-side fetch is the whole bug —
you can point it at things the server can reach but you can't: services bound to
loopback, the cloud metadata endpoint, and (because the fetcher isn't limited to
HTTP) the local filesystem.

Topology, all inside this one container:
  * Public app (this file, Flask)        -> 0.0.0.0:5000  (published to host 8081)
  * Internal ops service (http.server)   -> 127.0.0.1:8090 (NOT published; only
                                            reachable from inside the container,
                                            i.e. via SSRF through the public app)

Three intended stages, each a deeper SSRF objective:

  1. Internal service access  -> reach the ops console on loopback:8090.
     A naive host blocklist (localhost / 127.0.0.1 / metadata / ...) tries to
     stop you; it forgets that 0.0.0.0 (and other encodings) also hit loopback.
  2. Cloud metadata theft     -> pivot to the mock AWS metadata endpoint on the
     same internal service and steal the instance's IAM credentials.
  3. Scheme abuse             -> the fetcher speaks more than HTTP. file:// reads
     a local secret the web layer never exposed.

The fix is never a blocklist: validate against an allowlist of destinations,
restrict schemes to http/https, and resolve-then-pin the IP so it can't be a
loopback/link-local/private address. See SOLUTION.md.
"""
import json
import threading
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from flask import Flask, request, render_template_string

# ---------------------------------------------------------------------------
# The "sanitizer": a host blocklist. Looks defensive, leaks like a sieve —
# it enumerates a few spellings of "internal" and misses all the others
# (0.0.0.0, decimal/short IPs, and any non-http scheme entirely).
# ---------------------------------------------------------------------------
BLOCKED_HOST_SUBSTR = ("localhost", "127.0.0.1", "169.254.169.254", "metadata", "::1")


def host_is_blocked(url: str):
    host = (urlsplit(url).hostname or "").lower()
    for bad in BLOCKED_HOST_SUBSTR:
        if bad in host:
            return bad
    return None


# ===========================================================================
# INTERNAL OPS SERVICE — bound to 127.0.0.1:8090, never published to the host.
# Stands in for the private network an SSRF lets you pivot into.
# ===========================================================================
INTERNAL_ROUTES = {}


def internal(path):
    def deco(fn):
        INTERNAL_ROUTES[path] = fn
        return fn
    return deco


@internal("/")
def _root():
    return "text/plain", (
        "LinkPeek Internal Ops Console\n"
        "=============================\n"
        "Reachable only from the internal network. If you're reading this from\n"
        "outside, something is fetching it on your behalf.\n\n"
        "Endpoints:\n"
        "  /admin                              operations dashboard\n"
        "  /latest/meta-data/                  instance metadata (AWS-compatible)\n"
    )


@internal("/admin")
def _admin():
    return "text/html", (
        "<h1>🛠️ Ops Dashboard</h1>"
        "<p>Internal administration console. Access restricted to the VPC.</p>"
        "<ul>"
        "<li><b>Deploy token:</b> FLAG{ssrf_1nt3rnal_s3rv1c3_r34ch3d}</li>"
        "<li>Instance IAM role creds: <code>/latest/meta-data/iam/security-credentials/linkpeek-ec2-role</code></li>"
        "<li>Nightly DB backups written to <code>/opt/linkpeek/secrets/vault.txt</code> (root-only on disk)</li>"
        "</ul>"
    )


@internal("/latest/meta-data/")
def _md():
    return "text/plain", "iam/\n"


@internal("/latest/meta-data/iam/")
def _md_iam():
    return "text/plain", "security-credentials/\n"


@internal("/latest/meta-data/iam/security-credentials/")
def _md_roles():
    return "text/plain", "linkpeek-ec2-role\n"


@internal("/latest/meta-data/iam/security-credentials/linkpeek-ec2-role")
def _md_creds():
    return "application/json", json.dumps({
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIA5LINKPEEKEXAMPLE",
        "SecretAccessKey": "FLAG{ssrf_cl0ud_m3tadata_1am_l00t}",
        "Token": "IQoJb3JpZ2luX2VjEExampleSessionToken//////////wEXAMPLE",
        "Expiration": "2026-07-12T00:00:00Z",
    }, indent=2)


class InternalHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console quiet
        pass

    def do_GET(self):
        fn = INTERNAL_ROUTES.get(self.path)
        if fn is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 - not an internal endpoint\n")
            return
        ctype, body = fn()
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def start_internal():
    srv = ThreadingHTTPServer(("127.0.0.1", 8090), InternalHandler)
    srv.serve_forever()


# ===========================================================================
# PUBLIC APP — the SSRF vector.
# ===========================================================================
app = Flask(__name__)

PAGE = """
<!doctype html><html><head><title>LinkPeek</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#12203a}
 header{border-bottom:2px solid #234;padding-bottom:8px;margin-bottom:20px}
 .card{background:#f5f7fb;border:1px solid #dde;border-radius:8px;padding:16px;margin:12px 0}
 input[type=text]{width:100%;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:13px;
   padding:9px;border:1px solid #ccd;border-radius:6px}
 .btn{margin-top:10px;background:#0a58ca;color:#fff;border:0;padding:9px 16px;border-radius:6px;cursor:pointer;font-size:14px}
 .out{background:#0e1626;color:#d7e2ff;padding:12px 14px;border-radius:8px;white-space:pre-wrap;word-break:break-word;
   font-family:ui-monospace,monospace;font-size:12.5px;max-height:420px;overflow:auto}
 .err{color:#b00020} code{background:#e9ecf5;padding:1px 5px;border-radius:3px} .muted{font-size:12px;color:#789}
 label{font-size:13px;color:#456}
</style></head><body>
<header><h2>🔗 LinkPeek <span style="font-size:13px;color:#789">server-side link preview</span></h2></header>
{{ body|safe }}
</body></html>
"""


def shell(body, **kw):
    return render_template_string(PAGE, body=render_template_string(body, **kw))


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /peek\n", 200, {"Content-Type": "text/plain"}


@app.route("/", methods=["GET"])
def index():
    return shell(
        """
        <div class="card">
          <h3>Preview any link</h3>
          <p class="muted">Paste a URL and LinkPeek fetches it server-side and shows you what came back.</p>
          <form method="post" action="/peek">
            <label>URL</label>
            <input type="text" name="url" value="{{ prefill }}" autofocus>
            <div><button class="btn">Peek →</button></div>
          </form>
        </div>
        """,
        prefill="https://example.com/",
    )


@app.route("/peek", methods=["POST"])
def peek():
    url = request.form.get("url", "").strip()

    blocked = host_is_blocked(url)
    if blocked:
        return shell(
            """
            <div class="card">
              <p class="err">⛔ Blocked: destination host matches disallowed pattern
                 <code>{{ b }}</code>. Internal addresses are not permitted.</p>
              <p><a href="/">← Back</a></p>
            </div>
            """,
            b=blocked,
        ), 400

    # THE BUG: the server fetches an attacker-controlled URL, with no allowlist
    # and no scheme restriction, and hands the response body back to you.
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LinkPeek/1.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            raw = r.read(65536)
        try:
            preview = raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            preview = repr(raw)
    except urllib.error.URLError as e:
        preview = f"[fetch failed] {e}"
    except Exception as e:  # noqa: BLE001
        preview = f"[error] {type(e).__name__}: {e}"

    return shell(
        """
        <div class="card">
          <h3>Preview of <code>{{ url }}</code></h3>
          <div class="out">{{ out }}</div>
          <p style="margin-top:12px"><a href="/">← Peek another</a></p>
        </div>
        """,
        url=url,
        out=preview,
    )


if __name__ == "__main__":
    threading.Thread(target=start_internal, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
