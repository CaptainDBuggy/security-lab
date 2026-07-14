"""
PostPilot — advanced web CTF (Server-Side Template Injection -> RCE).

A "bulk message preview" tool. You write a notification template with
placeholders like {{ name }}, and the server renders it so you can preview the
result before a (pretend) send. The bug: your template string is fed straight
into Jinja2 via render_template_string(), so the placeholder engine will also
evaluate *any* expression you put between {{ }} — including ones that reach out
of the template sandbox and run code on the box.

Three intended stages, each a deeper post-exploitation objective off the SAME
injection point:

  1. Context leak      -> {{ config }} and friends dump the Flask app context,
                          which holds a secret the template was never meant to show.
  2. Sandbox escape/RCE-> the object graph (__class__ / __mro__ / __subclasses__)
                          reaches a process-spawning class; run a command, read a
                          file off disk.
  3. Environment loot  -> with command execution, pull secrets out of the
                          process environment (where real apps stash creds/keys).

DEFENSIVE NOTE (the lesson): a naive keyword BLOCKLIST is applied to your input
below. It blocks scary-looking words like "import" and "os". It does not work —
the subclasses gadget never needs those words. Blocklisting is theatre; the fix
is to never render untrusted input as a template (use a sandboxed environment or
plain string substitution). See SOLUTION.md.
"""
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- Stage 1 lands here -------------------------------------------------------
# A "secret" bolted onto app.config. Flask injects `config` into every template
# context, so an attacker who controls the template can read all of it.
app.config["SUPPORT_PIN"] = "FLAG{ss7i_c0nf1g_c0nt3xt_l34k}"

# --- The "sanitizer" the dev was proud of (Stage 2/3 sail right through it) ---
# Case-insensitive substring blocklist. Looks reasonable; stops nothing that
# matters, because the classic gadget spells out none of these words.
BLOCKLIST = ("import", " os", "os.", "system", "popen", "subprocess", "eval", "exec")


def looks_malicious(payload: str) -> bool:
    low = payload.lower()
    return any(bad in low for bad in BLOCKLIST)


PAGE = """
<!doctype html><html><head><title>PostPilot</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#12203a}
 header{border-bottom:2px solid #234;padding-bottom:8px;margin-bottom:20px}
 .card{background:#f5f7fb;border:1px solid #dde;border-radius:8px;padding:16px;margin:12px 0}
 textarea{width:100%;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:13px;padding:8px;border:1px solid #ccd;border-radius:6px}
 .btn{background:#1b5;color:#fff;border:0;padding:9px 16px;border-radius:6px;cursor:pointer;font-size:14px}
 .preview{background:#0e1626;color:#d7e2ff;padding:14px;border-radius:6px;white-space:pre-wrap;word-break:break-word}
 .err{color:#b00020} code{background:#e9ecf5;padding:1px 5px;border-radius:3px} label{font-size:13px;color:#456}
 .muted{font-size:12px;color:#789}
</style></head><body>
<header><h2>📨 PostPilot <span style="font-size:13px;color:#789">campaign message preview</span></h2></header>
{{ body|safe }}
</body></html>
"""


def shell(body, **kw):
    return render_template_string(PAGE, body=render_template_string(body, **kw))


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /preview\n", 200, {"Content-Type": "text/plain"}


@app.route("/", methods=["GET"])
def index():
    default = "Hi {{ name }}, your order {{ order_id }} from {{ company }} has shipped!"
    return shell(
        """
        <div class="card">
          <h3>Compose a campaign message</h3>
          <p class="muted">Use placeholders to personalise each recipient's message.
             Available fields: <code>{{ '{{ name }}' }}</code>,
             <code>{{ '{{ order_id }}' }}</code>, <code>{{ '{{ company }}' }}</code>.</p>
          <form method="post" action="/preview">
            <label>Message template</label>
            <textarea name="template" rows="4">{{ default }}</textarea>
            <p style="margin-top:10px"><button class="btn">Preview →</button></p>
          </form>
        </div>
        <p class="muted">Preview renders against a sample recipient before you send to the list.</p>
        """,
        default=default,
    )


@app.route("/preview", methods=["POST"])
def preview():
    template = request.form.get("template", "")

    if looks_malicious(template):
        # The dev's idea of "security". Congratulations to the dev.
        return shell(
            """
            <div class="card">
              <p class="err">⚠️ Your template contains a blocked keyword and was rejected
                 by our content filter.</p>
              <p><a href="/">← Back</a></p>
            </div>
            """
        ), 400

    # THE BUG: user-controlled `template` is rendered as a Jinja2 template, with a
    # sample recipient bound in. Anything in {{ }} is evaluated server-side.
    sample = {"name": "Dana Reyes", "order_id": "PP-100437", "company": "Northwind Co."}
    try:
        rendered = render_template_string(template, **sample)
    except Exception as e:  # noqa: BLE001 — show errors so previews are debuggable
        rendered = f"[render error] {type(e).__name__}: {e}"

    return shell(
        """
        <div class="card">
          <h3>Preview (sample recipient)</h3>
          <div class="preview">{{ out }}</div>
          <p style="margin-top:12px"><a href="/">← Edit template</a></p>
        </div>
        """,
        out=rendered,
    )


if __name__ == "__main__":
    # Stage 2 target lives on disk (written by the Dockerfile at build time).
    # Stage 3 target lives in the process environment (set via docker-compose).
    app.run(host="0.0.0.0", port=5000)
