# 📚 Bookworm — Intermediate Web CTF (SQL Injection)

A community library catalog with a single, classic weakness threaded through it:
**SQL injection**. One primitive, drilled three ways so it becomes automatic — you
should recognise the sink before you finish reading the page.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`bookworm-ctf`**. Publishes on host port **8086**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **bookworm-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-intermediate-09
docker compose up -d --build   # start (builds first time)
docker compose logs -f         # watch server logs
docker compose down            # remove entirely (fresh reset next 'up')
```

Open http://localhost:8086.

> ⚠️ **State note:** flags and data live in an in-container SQLite DB that resets on
> every `up`. `down` then `up` for a clean slate.

## The mission — 3 flags

Format `FLAG{...}`, increasing difficulty. **Every flag is SQL injection** — the same
primitive in three escalating flavours. That repetition is the point.

1. **Auth bypass (in-band boolean).** The members `/login` builds its query by pasting
   your username and password straight into the `WHERE` clause. Log in **without a
   valid password** and your dashboard hands you `flag1`.

2. **UNION-based extraction.** The catalog `/search?q=` drops your input into a
   `LIKE`. The results table shows two columns — *title* and *author*. Balance the
   column count and `UNION SELECT` your way into a table that isn't the book list to
   read `flag2`.

3. **Blind boolean-based extraction.** The book viewer `/book?id=<n>` injects a
   **numeric** id, but the page only tells you *whether a book matched* — it never
   reflects your injected data. Ask the database yes/no questions and read the answer
   off the page ("✅ in our catalog" vs "📕 no such book"). Drip `flag3` out one
   character at a time. (The book viewer is a separate service with its own database,
   so you **can't** shortcut this with the `/search` UNION — flag3 is blind-only.)

## How to think about it (the SQLi ladder)

- **Prove the injection first.** Before extracting anything, confirm the sink is
  injectable. A stray quote that changes the response (or throws a SQL error) is your
  signal. For the numeric sink, compare `id=1` vs `id=1 AND 1=1` vs `id=1 AND 1=2`.
- **Auth bypass** is just making the `WHERE` always true: think about what
  `' OR '1'='1' -- ` does to `... WHERE username='' OR '1'='1' -- ' AND password='...'`.
- **UNION** needs the column **count and types to line up**. Find the count with
  `ORDER BY n` (increment until it errors) or `UNION SELECT NULL,NULL`. Then swap the
  NULLs for the data you want. Enumerate the schema via `sqlite_master` if you need to
  learn table/column names.
- **Blind** is extraction without output. You already know the two flags live in a
  `secrets` table — recover the target value with `substr(...)` comparisons, one
  character per request (`... AND substr((SELECT value FROM ...),1,1)='F'`). Script it
  once you've done a few chars by hand — but do the first few by hand so you *feel* it.

## Tooling

- **Burp** (proxy on 8080) to intercept/replay, or plain `curl`.
- `sqlmap` will flatten all three — but solve each **by hand first**. The goal is to
  own the primitive yourself; automate only after you can do it manually.

## Reset / stop

```bash
docker compose down     # full reset
docker compose stop     # pause, keep state
docker compose start    # resume
```
