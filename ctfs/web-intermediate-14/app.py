"""
NetProbe — intermediate web CTF (OS Command Injection).

Deliberately vulnerable. One primitive — OS command injection — drilled in three
escalating flavours so it becomes automatic. You've injected into a database (SQLi) and
a browser (XSS); this one injects into a *shell*.

  1. Plain injection, output reflected  -> /ping runs `ping -c 1 <host>` via the shell.
                                           Chain your own command; its output comes back
                                           in the page. (flag1)

  2. Filter / quoting breakout          -> /lookup runs `nslookup <domain>` but first
                                           rejects a blacklist of "bad" characters
                                           (`; & | ` backtick and space). Get execution
                                           without any of them. (flag2)

  3. Blind injection, out-of-band exfil -> /monitor runs a command but returns NO output
                                           (discarded to /dev/null). Confirm the injection
                                           without seeing it (timing), then exfiltrate the
                                           flag through a channel you *can* read. (flag3)

Each tool's shell runs as a DIFFERENT low-privileged user (u1/u2/u3), and each flag file
is readable only by its own user. So one endpoint's RCE can't just read the other flags —
you have to actually solve each flavour. (That per-endpoint privilege split is also a nice
illustration of why least-privilege limits blast radius.)

NOTE(author): the fix is the same everywhere — never build a shell string from user input.
Use exec-style calls with an argument vector (`subprocess.run(["ping","-c","1",host])`,
no `shell=True`), validate/allow-list the input, and drop the shell entirely. Blacklists
(flag 2) don't work; there's always another separator. See SOLUTION.md.
"""
import os
import pwd
import html
import subprocess
from flask import Flask, request, render_template_string, send_from_directory

app = Flask(__name__)

PUBLIC_DIR = "/app/public"


def drop_to(username):
    """Return a preexec_fn that drops the child process to `username` before exec, so a
    given endpoint's command can only touch what that user can."""
    rec = pwd.getpwnam(username)

    def _fn():
        os.setgroups([])
        os.setgid(rec.pw_gid)
        os.setuid(rec.pw_uid)

    return _fn


def run_as(user, cmd, discard=False, timeout=15):
    """Run `cmd` through the shell as `user` (that's the whole vuln)."""
    if discard:
        subprocess.run(cmd, shell=True, preexec_fn=drop_to(user),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout)
        return ""
    p = subprocess.run(cmd, shell=True, preexec_fn=drop_to(user),
                       capture_output=True, text=True, timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


# ---------------------------------------------------------------- shared layout -----
SHELL = """
<!doctype html><html><head><title>NetProbe</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:780px;margin:36px auto;padding:0 16px;color:#231a12}
 header{border-bottom:2px solid #b45309;padding-bottom:8px;margin-bottom:18px}
 .card{background:#fdf6ec;border:1px solid #f0dcc0;border-radius:8px;padding:16px;margin:12px 0}
 a{color:#b45309} input{padding:6px;margin:4px 0;width:100%;box-sizing:border-box;font:inherit}
 label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#b45309;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font:inherit}
 .muted{color:#6b5a45;font-size:13px} code{background:#f3e6d2;padding:1px 4px;border-radius:3px}
 pre{background:#1c1710;color:#e7d9c4;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
 .err{color:#b00020} nav a{margin-right:10px}
</style></head><body>
<header><h2>📡 NetProbe <span class="muted">network diagnostics console</span></h2>
<nav><a href="/">home</a> · <a href="/ping">ping</a> · <a href="/lookup">dns lookup</a> ·
<a href="/monitor">uptime monitor</a></nav></header>
{{ body|safe }}
</body></html>
"""


def page(body):
    return render_template_string(SHELL, body=body)


def tool_form(action, label, field, value, placeholder, extra=""):
    return f"""
    <div class="card">
      <h3>{label}</h3>
      <form method="get" action="{action}">
        <label>{field}</label>
        <input name="{field}" value="{html.escape(value)}" placeholder="{placeholder}">
        <button class="btn">Run</button>
      </form>
      {extra}
    </div>
    """


# ---------------------------------------------------------------- routes ------------
@app.route("/")
def home():
    body = """
    <div class="card">
      <h3>Welcome to NetProbe</h3>
      <p class="muted">Internal network diagnostics for the ops team. Three tools:
        <a href="/ping">ping</a>, <a href="/lookup">DNS lookup</a>, and an
        <a href="/monitor">uptime monitor</a>.</p>
    </div>
    """
    return page(body)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = ""
    if host:
        # VULN #1: user input concatenated straight into a shell command.
        try:
            out = run_as("u1", f"ping -c 1 {host}")
        except subprocess.TimeoutExpired:
            out = "(timed out)"
    result = f"<pre>{html.escape(out)}</pre>" if host else ""
    body = tool_form("/ping", "Ping a host", "host", host, "e.g. 127.0.0.1", result)
    return page(body)


BLOCKLIST = [";", "&", "|", "`", " "]


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    out = ""
    if domain:
        # VULN #2: a blacklist "sanitiser" — reject some metacharacters, then still run
        # the input through the shell. Blacklists always miss something.
        bad = [c for c in BLOCKLIST if c in domain]
        if bad:
            out = f"Rejected: input contains a blocked character ({bad[0]!r})."
        else:
            try:
                out = run_as("u2", f"nslookup {domain}")
            except subprocess.TimeoutExpired:
                out = "(timed out)"
    result = f"<pre>{html.escape(out)}</pre>" if domain else ""
    note = ('<p class="muted">🛡️ For safety, this tool rejects the characters '
            '<code>; &amp; | ` </code> and spaces.</p>')
    body = tool_form("/lookup", "DNS lookup", "domain", domain, "e.g. example.com",
                     note + result)
    return page(body)


@app.route("/monitor")
def monitor():
    target = request.args.get("target", "")
    msg = ""
    if target:
        # VULN #3: injectable, but output is discarded — this is a BLIND sink.
        try:
            run_as("u3", f"ping -c 1 {target} > /dev/null 2>&1")
            msg = (f'<pre>Uptime check queued for "{html.escape(target)}".\n'
                   f'(No probe output is returned to the console.)</pre>')
        except subprocess.TimeoutExpired:
            msg = "<pre>Uptime check queued (worker still running…).</pre>"
    body = tool_form("/monitor", "Uptime monitor", "target", target,
                     "e.g. 127.0.0.1", msg)
    return page(body)


@app.route("/public/<path:fn>")
def public(fn):
    # Serves whatever the monitor worker (u3) drops into the public spool. Your
    # out-of-band read channel for the blind flag.
    try:
        return send_from_directory(PUBLIC_DIR, fn)
    except Exception:
        return "not found", 404


if __name__ == "__main__":
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000)
