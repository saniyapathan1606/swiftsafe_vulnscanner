# vuln_app.py -- Tiny vulnerable Flask app for local testing
from flask import Flask, request, render_template_string, make_response, redirect, url_for
import sqlite3

app = Flask(__name__)

# Simple in-memory DB for demonstration (not secure)
def init_db():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);")
    c.execute("INSERT INTO users (username,password) VALUES ('admin','admin123');")
    conn.commit()
    return conn

DB_CONN = init_db()

HOME_HTML = """
<h1>Welcome to Local Vulnerable App</h1>
<ul>
<li><a href="/search">Search (reflected param)</a></li>
<li><a href="/login">Login form</a></li>
<li><a href="/error">Trigger error (simulated)</a></li>
<li><a href="/sensitive/.env">Exposed .env</a></li>
</ul>
"""

@app.route("/")
def home():
    # intentionally omit some security headers (for scanner to detect)
    resp = make_response(render_template_string(HOME_HTML))
    # Do not set CSP, X-Frame-Options etc. (so scanner sees missing headers)
    resp.headers['X-Powered-By'] = 'Flask/LocalDemo'
    return resp

@app.route("/search")
def search():
    # reflected parameter (harmless) — useful to test reflection detection
    q = request.args.get("q", "")
    html = f"""
    <h2>Search results for: {q}</h2>
    <p>Showing results (demo only)</p>
    <form action="/search" method="get">
      <input name="q" value="{q}">
      <input type="submit" value="Search">
    </form>
    """
    return html

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        # intentionally vulnerable SQL (do NOT exploit externally)
        c = DB_CONN.cursor()
        try:
            query = f"SELECT username FROM users WHERE username='{user}' AND password='{pw}'"
            c.execute(query)
            row = c.fetchone()
            if row:
                return "<h3>Login successful (demo)</h3>"
            else:
                return "<h3>Login failed</h3>"
        except Exception as e:
            return f"<pre>Database error: {e}</pre>"
    return '''
    <h2>Login</h2>
    <form method="post">
      <input name="username" placeholder="username"><br>
      <input name="password" placeholder="password"><br>
      <input type="submit" value="Login">
    </form>
    '''

@app.route("/error")
def error():
    # Simulate an error trace in the response body (for pattern detection)
    return "<pre>Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>\n    raise Exception('demo error')\nException: demo error</pre>", 500

@app.route("/sensitive/.env")
def envfile():
    # Simulate exposed config file (scanner should flag accessible sensitive path)
    return "SECRET_KEY=supersecret\nDB_PASSWORD=password123\n", 200, {"Content-Type":"text/plain"}

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\n", 200, {"Content-Type":"text/plain"}

@app.route("/sitemap.xml")
def sitemap():
    return '<?xml version="1.0"?><urlset></urlset>', 200, {"Content-Type":"application/xml"}

if __name__ == "__main__":
    # Run on localhost:5000
    app.run(host="127.0.0.1", port=5000, debug=False)
