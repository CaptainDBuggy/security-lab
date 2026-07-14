"""
Keyring — internal document viewer (the LFI surface).

The vulnerability is a classic path-traversal / Local File Inclusion in the
document viewer: it joins a user-supplied filename onto a base directory with no
sanitization, so `?file=../../../../etc/passwd` (or an absolute path) escapes the
docs folder and reads arbitrary files the web user can access.

The app runs as the low-priv www-data user, so LFI can read app files (including
a forgotten credential backup) but NOT /etc/shadow. The intended path is: LFI the
backup -> crack the hash -> SSH in.
"""
from flask import Flask, request, Response
import os

app = Flask(__name__)
BASE = "/var/www/keyring/pages"

SHELL = """<!doctype html>
<html><head><title>Keyring — Docs</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:820px;margin:44px auto;padding:0 18px;color:#101828;line-height:1.5}}
 header{{border-bottom:3px solid #6d28d9;padding-bottom:10px;margin-bottom:22px}}
 .tag{{color:#6d28d9;font-weight:600;letter-spacing:.5px;font-size:13px;text-transform:uppercase}}
 nav a{{margin-right:14px;color:#6d28d9;text-decoration:none;font-weight:600}}
 pre{{background:#0b1220;color:#d7e3f4;padding:16px;border-radius:8px;overflow:auto;font-size:13px}}
 form{{margin:14px 0}} input{{padding:7px;border:1px solid #cbd5e1;border-radius:6px}}
 button{{padding:7px 14px;border:0;border-radius:6px;background:#6d28d9;color:#fff;font-weight:600;cursor:pointer}}
 footer{{margin-top:30px;color:#667085;font-size:12px;border-top:1px solid #e3e8ef;padding-top:12px}}
</style></head><body>
<header><div class="tag">Keyring</div><h1>Team documentation</h1></header>
<nav>
  <a href="/view?file=welcome.txt">Welcome</a>
  <a href="/view?file=changelog.txt">Changelog</a>
</nav>
<form method="GET" action="/view">
  <input type="text" name="file" value="{file}" size="48">
  <button type="submit">Open</button>
</form>
<pre>{content}</pre>
<footer>Keyring &middot; docs node &middot; internal only.</footer>
</body></html>
"""


@app.route("/")
def index():
    return view_file("welcome.txt")


@app.route("/view")
def view():
    return view_file(request.args.get("file", "welcome.txt"))


def view_file(fname):
    # --- VULNERABILITY: no path sanitization; traversal & absolute paths work ---
    path = os.path.join(BASE, fname)
    try:
        with open(path, "r", errors="replace") as fh:
            content = fh.read()
    except Exception as exc:
        content = f"[could not open {fname}: {exc}]"
    esc = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    fesc = fname.replace('"', "&quot;")
    return Response(SHELL.format(file=fesc, content=esc))


if __name__ == "__main__":
    # www-data can't bind :80, so listen high; compose maps 8085->8000.
    app.run(host="0.0.0.0", port=8000)
