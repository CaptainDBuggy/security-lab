"""
Bookworm — intermediate web CTF (SQL Injection).

Deliberately vulnerable. One primitive — SQL injection — drilled in three escalating
flavours so it becomes automatic:

  1. Auth bypass (in-band, boolean)   -> /login concatenates username+password into
                                         the WHERE clause. `' OR '1'='1' -- ` logs in.
  2. UNION-based extraction           -> /search LIKEs the query straight into SQL.
                                         Balance the columns and UNION out a secret.
  3. Blind boolean-based extraction   -> /book?id=<n> injects a numeric id and only
                                         reveals *whether* a row matched. No data is
                                         reflected — you drip the flag out one
                                         character at a time via true/false pages.

Everything else (sessions, other queries) is intentionally boring. The lesson is the
injection itself: recognise the sink, prove the injection, then extract.

NOTE(author): parameterised queries would kill all three bugs. That's the point of
the SOLUTION.md lesson notes — every sink here should have used `?` placeholders.
"""
import os
import sqlite3
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Two separate datastores on purpose. The members/catalog service (login + search)
# uses MAIN_DB; the standalone book-viewer microservice uses BOOKS_DB. Because the
# UNION sink in /search can only reach MAIN_DB, flag3 is NOT dumpable in-band — it
# lives only behind the blind sink, so the blind technique is actually required.
MAIN_DB = "/tmp/bookworm.db"
BOOKS_DB = "/tmp/booksvc.db"

FLAG1 = "FLAG{sql1_4uth_byp4ss_0r_1eq1}"        # reward for the login auth bypass
FLAG2 = "FLAG{un10n_s3l3ct_d4t4_3xf1ltr8}"      # MAIN_DB.secrets, pulled via UNION
FLAG3 = "FLAG{bl1nd_b00l3an_dr1p_dr1p}"         # BOOKS_DB.audit, dripped via blind only

BOOKS = [
    (1, "The Pragmatic Programmer", "Hunt & Thomas", 1999),
    (2, "Clean Code", "Robert C. Martin", 2008),
    (3, "The Web Application Hacker's Handbook", "Stuttard & Pinto", 2011),
    (4, "SQL for Smarties", "Joe Celko", 1995),
    (5, "Designing Data-Intensive Applications", "Martin Kleppmann", 2017),
]


def get_db(path=MAIN_DB):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    # --- MAIN_DB: users + catalog + the UNION-reachable secret (flag2) ---
    con = get_db(MAIN_DB)
    con.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS books;
        DROP TABLE IF EXISTS secrets;

        CREATE TABLE users   (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE books   (id INTEGER PRIMARY KEY, title TEXT, author TEXT, year INTEGER);
        CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT);
        """
    )
    # First row is a normal member — an auth bypass logs you in as this identity.
    con.executemany(
        "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
        [
            (1, "reader", "reader-" + os.urandom(6).hex()),   # password unknown to player
            (2, "libadmin", "adm1n-" + os.urandom(8).hex()),
        ],
    )
    con.executemany(
        "INSERT INTO books (id, title, author, year) VALUES (?, ?, ?, ?)", BOOKS
    )
    con.execute("INSERT INTO secrets (id, name, value) VALUES (?, ?, ?)",
                (1, "catalog_license", FLAG2))
    con.commit()
    con.close()

    # --- BOOKS_DB: the book-viewer service's own store. Same catalog, plus an
    #     `audit` table holding flag3 — only reachable through the blind /book sink. ---
    con = get_db(BOOKS_DB)
    con.executescript(
        """
        DROP TABLE IF EXISTS books;
        DROP TABLE IF EXISTS audit;

        CREATE TABLE books (id INTEGER PRIMARY KEY, title TEXT, author TEXT, year INTEGER);
        CREATE TABLE audit (id INTEGER PRIMARY KEY, name TEXT, token TEXT);
        """
    )
    con.executemany(
        "INSERT INTO books (id, title, author, year) VALUES (?, ?, ?, ?)", BOOKS
    )
    con.execute("INSERT INTO audit (id, name, token) VALUES (?, ?, ?)",
                (1, "audit_token", FLAG3))
    con.commit()
    con.close()


SHELL = """
<!doctype html><html><head><title>Bookworm</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1a1a2e}
 header{border-bottom:2px solid #2d3a2e;padding-bottom:8px;margin-bottom:20px}
 .card{background:#f5f5ef;border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}
 .flag{background:#132a13;color:#c8f7c5;padding:8px 10px;border-radius:6px;font-family:monospace}
 a{color:#2f5d34} input{padding:6px;margin:4px 0} label{display:block;font-size:13px;margin-top:8px}
 .btn{background:#2f5d34;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer}
 .err{color:#b00020} code{background:#eee;padding:1px 4px;border-radius:3px}
 table{border-collapse:collapse;width:100%} td,th{border:1px solid #ccc;padding:6px;text-align:left;font-size:14px}
 .muted{color:#666;font-size:13px}
</style></head><body>
<header><h2>📚 Bookworm <span class="muted">community library catalog</span></h2>
<nav><a href="/">home</a> &middot; <a href="/search">search</a> &middot;
<a href="/book?id=1">browse</a> &middot; <a href="/login">login</a></nav></header>
{{ body|safe }}
</body></html>
"""


def page(body):
    return render_template_string(SHELL, body=body)


@app.route("/")
def index():
    return page(
        '<div class="card"><h3>Welcome to Bookworm</h3>'
        "<p>Search the catalog, browse a book, or log in to the members area.</p>"
        '<p class="muted">Members get a reading token on their dashboard.</p></div>'
        '<div class="card"><b>Try:</b> <a href="/search?q=code">search “code”</a> '
        '&middot; <a href="/book?id=3">book #3</a></div>'
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        con = get_db()
        # --- VULN #1: string-built auth query -> injectable / auth bypass ---
        q = ("SELECT id, username FROM users "
             "WHERE username = '%s' AND password = '%s'" % (u, p))
        try:
            row = con.execute(q).fetchone()
        except sqlite3.Error as e:
            con.close()
            return page(f'<div class="card err">SQL error: {e}</div>')
        con.close()
        if row:
            session["user"] = row["username"]
            return redirect("/dashboard")
        return page('<div class="card err">Invalid credentials.</div>' + _login_form())
    return page(_login_form())


def _login_form():
    return (
        '<div class="card"><h3>Members login</h3>'
        '<form method="post">'
        '<label>Username</label><input name="username" autofocus>'
        '<label>Password</label><input name="password" type="password">'
        '<br><button class="btn">Sign in</button></form>'
        '<p class="muted">Members only. Don’t have an account? Ask a librarian.</p></div>'
    )


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return page(
        f'<div class="card"><h3>👋 Welcome back, {session["user"]}</h3>'
        "<p>Your member reading token:</p>"
        f'<p class="flag">{FLAG1}</p>'
        '<p class="muted">Tip: the catalog search and the book viewer both read '
        "straight from our database.</p></div>"
        '<div class="card"><a href="/logout">log out</a></div>'
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q")
    form = (
        '<div class="card"><form method="get">'
        '<label>Search the catalog by title</label>'
        f'<input name="q" value="{q or ""}" placeholder="e.g. code">'
        '<button class="btn">Search</button></form></div>'
    )
    if not q:
        return page(form)
    con = get_db()
    # --- VULN #2: query interpolated into a LIKE -> UNION-injectable ---
    sql = ("SELECT title, author FROM books "
           "WHERE title LIKE '%%%s%%'" % q)
    try:
        rows = con.execute(sql).fetchall()
    except sqlite3.Error as e:
        con.close()
        return page(form + f'<div class="card err">SQL error: {e}</div>')
    con.close()
    body = form + '<div class="card"><table><tr><th>Title</th><th>Author</th></tr>'
    for r in rows:
        body += f"<tr><td>{r['title']}</td><td>{r['author']}</td></tr>"
    body += "</table>"
    if not rows:
        body += '<p class="muted">No matches.</p>'
    body += "</div>"
    return page(body)


@app.route("/book")
def book():
    bid = request.args.get("id", "1")
    con = get_db(BOOKS_DB)
    # --- VULN #3: numeric id concatenated -> boolean-blind injectable.
    #     We fetch a row but NEVER render any of its columns: the page only reveals
    #     whether a row matched (availability). That closes any UNION/reflection
    #     shortcut — extracting data here must be done blind, one boolean at a time. ---
    sql = ("SELECT title FROM books WHERE id = %s" % bid)
    try:
        row = con.execute(sql).fetchone()
    except sqlite3.Error as e:
        con.close()
        return page(f'<div class="card err">SQL error: {e}</div>')
    con.close()
    verdict = ("✅ This title is in our catalog."
               if row else "📕 No such book in the catalog.")
    return page(f'<div class="card"><h3>Catalog availability</h3>'
                f'<p class="muted">{verdict}</p></div>')


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
