# 🚩 LinkPeek — SOLUTION (SPOILERS)

> ⛔⛔⛔ **STOP.** Full answers to all three flags below. Close this if you're still
> solving. Kept as a personal write-up, not to read while playing.
>
> .
>
> .
>
> .
>
> .
>
> .
>
> .

---

## Recon — confirm SSRF

The `/peek` form fetches your URL **server-side**. Point it at a URL you control
(or just at the box itself) and notice the response body comes back to you —
proof the *server* is making the request, not your browser. From there the
question is: what can the server reach that you can't?

The interesting internal target is a service on **loopback port 8090** that
isn't published to the host. You can't `curl` it directly; the server can.

## The filter

The app blocks a URL whose **host** contains any of:
`localhost`, `127.0.0.1`, `169.254.169.254`, `metadata`, `::1`.
It's a substring blocklist on the hostname only — so it misses every other way
to write a loopback address, and it ignores the URL **scheme** entirely.

## Flag 1 — internal service access (`FLAG{ssrf_1nt3rnal_s3rv1c3_r34ch3d}`)

`http://127.0.0.1:8090/` is blocked. But `0.0.0.0` also routes to loopback on
Linux and isn't on the list:

```bash
curl -s localhost:8081/peek --data-urlencode 'url=http://0.0.0.0:8090/'      # internal index
curl -s localhost:8081/peek --data-urlencode 'url=http://0.0.0.0:8090/admin' # -> Flag 1
```

The `/admin` ops dashboard holds **Flag 1**, plus two breadcrumbs you'll use
next: the IAM metadata path, and the on-disk backup path for Flag 3.

**Other loopback encodings that also sail past the filter** (all verified here):
- Decimal: `http://2130706433:8090/admin`
- Short form: `http://127.1:8090/admin`
- Octal: `http://0177.0.0.1:8090/admin`

(`[::1]` is correctly blocked, and the internal service is IPv4-only anyway.)

**Lesson:** a blocklist of address *spellings* can't win — one canonical
destination has many textual forms. Validate by resolving the host and checking
the resulting IP against deny-ranges, not by string-matching the URL.

## Flag 2 — cloud metadata / IAM credential theft (`FLAG{ssrf_cl0ud_m3tadata_1am_l00t}`)

Cloud instances expose a metadata service (in AWS, `http://169.254.169.254/`)
that returns the box's IAM role credentials to anything that requests it from
inside — the single most valuable SSRF target in the real world. This box mirrors
it on the internal service. The host word `metadata` and the IP are blocked, but
you already have a loopback bypass, and the metadata lives at the AWS path:

```bash
curl -s localhost:8081/peek --data-urlencode \
  'url=http://0.0.0.0:8090/latest/meta-data/iam/security-credentials/linkpeek-ec2-role'
```

The JSON `SecretAccessKey` field is **Flag 2**. In a real engagement those keys
would let you call the cloud API as the instance — the classic pivot from "a web
bug" to "the whole account."

**Lesson:** SSRF + a metadata service = credential compromise. Modern clouds
mitigate with IMDSv2 (a session-token handshake), but SSRF that can set headers
or follow redirects often defeats naive versions. Don't expose credentials to
anything that can forge a request from the host.

## Flag 3 — scheme abuse / local file read (`FLAG{ssrf_f1l3_sch3m3_l0cal_r34d}`)

The fetcher uses `urllib.request.urlopen`, which speaks more than HTTP — including
`file://`. The filter only inspects the *host*, and a `file://` URL has no host,
so it passes untouched. The `/admin` page told you where the backup lives:

```bash
curl -s localhost:8081/peek --data-urlencode 'url=file:///opt/linkpeek/secrets/vault.txt'
```

That reads the root-only file straight off disk → **Flag 3**. (`file:///etc/passwd`
is the classic proof-of-concept; the vault path is the flag.)

**Lesson:** an SSRF is only as narrow as the schemes its client allows. `file://`
gives arbitrary file read; `gopher://` can forge raw TCP to smuggle requests at
Redis/HTTP/SMTP. Always restrict the fetcher to an explicit `{http, https}`
allowlist.

---

## Root cause & the fix

One bug — the server fetches a URL you control — three escalations. The blocklist
made it *look* defended while stopping nothing. Real remediation:

- **Allowlist destinations**, don't blocklist them. Permit only the exact hosts
  the feature needs.
- **Restrict schemes** to `http`/`https` explicitly.
- **Resolve, then pin.** Resolve the hostname to an IP, reject loopback /
  link-local / private / multicast ranges, and connect to *that IP* so DNS can't
  rebind between check and fetch.
- **Don't follow redirects** blindly (a `302` to `169.254.169.254` defeats a
  host check done only on the first URL).
- **Protect the metadata service** (IMDSv2) and keep secrets off any surface a
  forged request can reach.

### Full flag list
1. `FLAG{ssrf_1nt3rnal_s3rv1c3_r34ch3d}`
2. `FLAG{ssrf_cl0ud_m3tadata_1am_l00t}`
3. `FLAG{ssrf_f1l3_sch3m3_l0cal_r34d}`
