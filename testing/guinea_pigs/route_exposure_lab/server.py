"""Route exposure lab: one stdlib HTTP server, four roles (ROLE=main|twin|hostile|outsider).

Every request is appended to /tmp/hits.jsonl (method, path, which credentials
rode on it, Origin, Range, status) so a validator can assert the requests a scan
BUILT. There is no HTTP surface for the log: a scan would discover it. Behaviour
switches are files: `touch /tmp/flags/<name>` inside the container.

Every fake secret is generated at start into /tmp/lab-secrets.json, never
committed: a format-valid fake in the repository would trip the secret
scanners. Fake e-mails (userN@lab.invalid) are not secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import ssl
import string
import struct
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROLE = os.environ.get("ROLE", "main")
HITS = "/tmp/hits.jsonl"
FLAGS = "/tmp/flags"
SECRETS_FILE = "/tmp/lab-secrets.json"
OUTSIDER = os.environ.get("OUTSIDER_IP", "172.25.0.96")
_LOCK = threading.Lock()

USERS = [{"id": i, "email": f"user{i}@lab.invalid", "name": f"Lab User {i}", "role": "user"}
         for i in range(1, 26)]
ORDER = {"id": 42, "item": "widget", "quantity": 3, "status": "shipped", "notes": "n" * 60}


def _rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _make_secrets() -> dict:
    values = {
        "env_db_password": "LAB-NOT-A-SECRET-" + secrets.token_hex(6),
        # A ghp_ value with a random body is never a live token.
        "github_token": "ghp_" + _rand(36),
        "git_blob_secret": "LAB-NOT-A-SECRET-" + secrets.token_hex(6),
        "heap_password": "LAB-NOT-A-SECRET-" + secrets.token_hex(6),
        "heap_jdbc": "jdbc:postgresql://db.lab.invalid:5432/app?password=LAB-NOT-A-SECRET-" + secrets.token_hex(4),
        "heap_aws_key": "AKIA" + _rand(16, string.ascii_uppercase + string.digits),
        "werkzeug_secret": _rand(20),
    }
    with open(SECRETS_FILE, "w") as fh:
        json.dump(values, fh)
    return values


SECRETS = _make_secrets()
os.makedirs(FLAGS, exist_ok=True)


def flag(name: str) -> bool:
    return os.path.exists(os.path.join(FLAGS, name))


# ---------------------------------------------------------------------------
# A small, real git repository served as loose objects (no info/refs)
# ---------------------------------------------------------------------------

def _obj(kind: str, body: bytes, store: dict) -> bytes:
    raw = f"{kind} {len(body)}".encode() + b"\0" + body
    sha = hashlib.sha1(raw).digest()
    store[sha.hex()] = zlib.compress(raw)
    return sha


def _tree(entries: list, store: dict) -> bytes:
    body = b"".join(f"{mode} {name}".encode() + b"\0" + sha for mode, name, sha in sorted(entries, key=lambda e: e[1]))
    return _obj("tree", body, store)


def _build_repo() -> tuple[dict, str]:
    store: dict = {}
    files = {
        "README.md": b"# Lab portal\n\nInternal demo application for the route exposure lab.\n",
        "requirements.txt": b"flask==3.0.0\nrequests==2.32.0\n",
        "app.py": b"from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    return 'ok'\n",
        "Dockerfile": b"FROM python:3.12-slim\nCOPY . /app\n",
    }
    blobs = {name: _obj("blob", body, store) for name, body in files.items()}
    settings = f"DEBUG = False\nSECRET_KEY = '{SECRETS['git_blob_secret']}'\n".encode()
    config_blob = _obj("blob", settings, store)
    config_tree = _tree([("100644", "settings.py", config_blob)], store)
    tests_tree = _tree([("100644", "test_app.py", _obj("blob", b"def test_ok():\n    assert True\n", store))], store)
    root1 = _tree([("100644", n, s) for n, s in blobs.items() if n != "Dockerfile"], store)
    author = b"author Lab Dev <dev@lab.invalid> 1700000000 +0000\ncommitter Lab Dev <dev@lab.invalid> 1700000000 +0000\n"
    c1 = _obj("commit", b"tree " + root1.hex().encode() + b"\n" + author + b"\nInitial import\n", store)
    root2 = _tree([("100644", n, s) for n, s in blobs.items()] + [("40000", "config", config_tree),
                                                                  ("40000", "tests", tests_tree)], store)
    c2 = _obj("commit", b"tree " + root2.hex().encode() + b"\nparent " + c1.hex().encode() + b"\n"
              + author + b"\nAdd settings and tests\n", store)
    return store, c2.hex()


GIT_OBJECTS, GIT_HEAD = _build_repo() if ROLE == "main" else ({}, "")

# ---------------------------------------------------------------------------
# Static bodies
# ---------------------------------------------------------------------------

HEADERS_COMMON = {"Server": "LabServer/1.0", "X-Powered-By": "Lab"}

LANDING = """<!doctype html><html><head><title>Lab Portal</title>
<script src="/static/app.js"></script></head><body>
<h1>Lab Portal</h1>
<p>Welcome to the lab portal. Read the <a href="/api/admin/help">administrator help</a>,
the <a href="/openapi.json">API documentation</a> or <a href="/login">sign in</a>.</p>
<p><a href="/settings">Settings</a> <a href="/config.php">Configuration</a>
<a href="/internal/portal">Staff area</a></p>
{uploads}
</body></html>"""

APP_JS = """// Lab portal client bundle
const api = {
  order: () => fetch('/api/v2/orders/42'),
  me: () => fetch('/api/users/me'),
  exportUsers: () => fetch('/internal/users/export'),
  reportError: () => fetch('/debug/error'),
  debugConsole: () => fetch('/console-open'),
  logout: () => fetch('/logout'),
  reset: () => fetch('/account/reset'),
  track: () => fetch('http://OUTSIDER/api/track'),
  myOrder: () => fetch('/api/orders/7'),
  profile: () => fetch('/api/profile'),
  adminStats: () => fetch('/api/admin/stats'),
  adminReports: () => fetch('/api/admin/reports'),
};
const routes = [{ path: '/admin/dashboard', component: 'AdminDashboard' },
                { path: '/admin/reports', component: 'AdminReports' }];
// The menu hides admin pages from members; a direct visit still mounts the component,
// which calls its API (client-side gating only).
const mounts = { '/admin/dashboard': api.adminStats, '/admin/reports': api.adminReports };
document.addEventListener('DOMContentLoaded', function () {
  var call = mounts[location.pathname];
  if (call) call().then(function (r) { return r.text(); }).then(function (t) {
    var el = document.getElementById('app'); if (el) el.textContent = t.slice(0, 200); });
});
(function(){ var s=document.createElement('script'); s.src='http://OUTSIDER/widget.js'; document.head.appendChild(s); })();
"""

#: The SPA's admin pages: a shell the client-side router fills in.
SPA_ADMIN = """<!doctype html><html><head><title>Lab Portal</title>
<script src="/static/app.js"></script></head><body><nav>Lab Portal</nav>
<div id="app">Loading the administration page for your account...</div></body></html>"""

#: Spring actuator's route table: one open internal route, one locked, one templated.
MAPPINGS = {"contexts": {"application": {"mappings": {"dispatcherServlets": {"dispatcherServlet": [
    {"handler": h, "details": {"requestMappingConditions": {"patterns": [p], "methods": ["GET"]}}}
    for h, p in (("BillingController#reconcile()", "/api/internal/billing/reconcile"),
                 ("BillingController#close()", "/api/internal/billing/close"),
                 ("OrderController#get(Long)", "/api/orders/{id}"),
                 ("EnvironmentEndpoint#environment()", "/actuator/env"))]}}}}}

#: Fingerprints httpx names (Spring via its application-context header, Laravel via
#: its session cookie), so the v2 framework seeds fire on main and twin.
FRAMEWORK_HEADERS = {"X-Application-Context": "lab-portal:8080",
                     "Set-Cookie": "laravel_session=lab; Path=/; HttpOnly"}

OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Lab API", "version": "2.0.0"},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/api/v2/orders/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True,
                            "schema": {"type": "integer"}, "example": 42}],
            "get": {"operationId": "getOrder", "security": [{"bearer": []}],
                    "responses": {"200": {"description": "the order"}}},
            "delete": {"operationId": "deleteOrder", "security": [{"bearer": []}],
                       "responses": {"204": {"description": "deleted"}}},
        },
        "/api/v2/reports/export": {
            "get": {"operationId": "exportReport", "security": [{"bearer": []}],
                    "responses": {"200": {"description": "the report"}}}},
        "/api/status": {
            "get": {"operationId": "status", "security": [], "responses": {"200": {"description": "ok"}}}},
    },
}

DJANGO_DEBUG = """<!DOCTYPE html><html><head><title>OperationalError at /debug/error</title></head><body>
<h1>OperationalError at /debug/error</h1><table><tr><th>Django Version:</th><td>4.2</td></tr></table>
<div id="explanation"><p>You're seeing this error because you have <code>DEBUG = True</code> in your
Django settings file. Change that to <code>False</code>, and Django will display a standard page.</p></div>
</body></html>"""

WERKZEUG = """<!doctype html><html><head><title>Werkzeug Debugger</title>
<script>var TRACEBACK = 140; var CONSOLE_MODE = true; var EVALEX = true; var EVALEX_TRUSTED = false;
var SECRET = "{secret}";</script></head><body><div class="debugger"><h1>Interactive Console</h1>
<div class="pin-prompt"><div class="inner"><h3>Console Locked</h3>
<p>The console is locked and needs to be unlocked by entering the PIN.</p>
<form><p>PIN: <input type=text name=pin size=14><input type=submit value="Confirm Pin"></form>
</div></div><p>__debugger__ console</p></div></body></html>"""

WERKZEUG_OPEN = """<!doctype html><html><head><title>Werkzeug Debugger</title>
<script>var TRACEBACK = 140; var CONSOLE_MODE = true; var EVALEX = true; var EVALEX_TRUSTED = true;
var SECRET = "{secret}";</script></head><body><div class="debugger"><h1>Interactive Console</h1>
<div class="console"><div class="inner" data-frm="{frm}"><h2>Interactive Console</h2>
<p>In this console you can execute Python expressions in the context of the application.
__debugger__</p></div></div></div></body></html>"""

PHPINFO = """<!DOCTYPE html><html><head><title>phpinfo()</title></head><body><div class="center">
<table><tr class="h"><td><h1 class="p">PHP Version 8.2.12</h1></td></tr></table>
<table><tr><td class="e">System </td><td class="v">Linux lab 6.1</td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI</td></tr></table></div></body></html>"""

# A disguised login wall (plan S18b, Jev hook B): a 200 whose page is only a sign-in form,
# with nothing in its path or title the deterministic page check reads as a login. The
# path word makes it a lead, so hook B is asked about it.
PORTAL = """<!doctype html><html><head><title>Staff area</title></head><body>
<h1>Staff area</h1><p>Members of staff reach the rota, the payroll documents and the internal
directory here. Identify yourself with your staff account to continue.</p>
<form method="post" action="/session"><label>Username <input name="username"></label>
<label>Password <input name="password" type="password"></label><button>Continue</button></form>
</body></html>"""

HELP = """<!doctype html><html><head><title>Administrator help</title></head><body>
<h1>Administrator help</h1><p>This page explains how administrators manage the lab portal:
how to reset a password, how to export reports, and whom to contact for support. It is public
documentation and contains no data.</p></body></html>"""

SPA_SHELL = """<!doctype html><html><head><title>Hostile app</title></head><body>
<div id="root"></div><script src="/static/hostile.js"></script>
<noscript>This application needs JavaScript to run in your browser.</noscript></body></html>"""

HOSTILE_JS = """// hostile bundle
fetch('/spa/admin'); fetch('/spa/internal/users');
fetch('/api/missing/internal'); fetch('/wall/admin');
fetch('/big'); fetch('/slow'); fetch('/redirect-internal'); fetch('/cookie-trap');
fetch('/rate/internal/a'); fetch('/rate/internal/b'); fetch('/rate/internal/c'); fetch('/rate/internal/d');
fetch('/reset-conn'); fetch('/xss-snippet'); fetch('/api/public-cors');
fetch('/internal/caf%C3%A9'); fetch('/internal/a/../b'); fetch('/internal/LONGSEG');
fetch('http://OUTSIDER/api/internal/collect'); fetch('http://169.254.169.254/latest/meta-data/');
""".replace("LONGSEG", "x" * 2000)


def _hostile_openapi() -> dict:
    paths = {f"/api/bulk/item{i}": {"get": {"responses": {"200": {"description": "x"}}}} for i in range(6000)}
    paths["/api/internal/audit"] = {"get": {"security": [{"k": []}], "responses": {"200": {"description": "x"}}}}
    return {"openapi": "3.0.3", "info": {"title": "Bulk", "version": "1"},
            "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-K"}}},
            "paths": paths}


HOSTILE_OPENAPI = json.dumps(_hostile_openapi()).encode() if ROLE == "hostile" else b""
_RATE = {"window": 0.0, "count": 0}
def _zlib_bomb() -> bytes:
    """A loose object that inflates to 256 MiB of zeros from a few hundred KiB: the git
    walk must cap its inflate, not trust the object's size."""
    comp = zlib.compressobj(9)
    chunk = b"\0" * (1 << 20)
    return b"".join(comp.compress(chunk) for _ in range(256)) + comp.flush()


GIT_BOMB = _zlib_bomb() if ROLE == "hostile" else b""
BOMB_HASH = "0b" + "e" * 38

#: main /api/profile's shared cache: query string -> (body, stored at). Only a URL with
#: a query is stored, so the agent's cache-buster probe can be proven while a plain
#: recon re-run within the TTL never meets a stored body (runs stay deterministic).
_PROFILE_CACHE: dict = {}
_PROFILE_TTL = 600


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def _authed(headers) -> bool:
    if headers.get("Authorization") == "Bearer lab-token":
        return True
    if headers.get("X-API-Key") == "lab-key":
        return True
    return "sid=lab-user-1" in (headers.get("Cookie") or "")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LabServer/1.0"
    sys_version = ""

    def end_headers(self):
        # One request per connection on the hostile host: its /reset-conn RST otherwise
        # took down whatever a client had queued behind it on the same kept-alive
        # connection, and jsluice's httpx verify lost bundle URLs at random.
        if ROLE == "hostile":
            self.send_header("Connection", "close")
        super().end_headers()

    def log_message(self, *args):
        pass

    # -- plumbing --------------------------------------------------------------

    def _log(self, status: int) -> None:
        h = self.headers
        # The framework fingerprint cookie is not a credential: a browser that visited
        # the landing page sends it back, and it says nothing about a session.
        cookies = [c.strip() for c in (h.get("Cookie") or "").split(";") if c.strip()]
        credential_cookies = [c for c in cookies if not c.startswith("laravel_session=")]
        entry = {
            "t": time.time(), "method": self.command, "path": self.path, "status": status,
            "auth": bool(h.get("Authorization")), "cookie": bool(credential_cookies),
            "api_key": bool(h.get("X-API-Key")), "origin": h.get("Origin") or "",
            "range": h.get("Range") or "", "tls": isinstance(self.connection, ssl.SSLSocket),
        }
        if ROLE == "outsider":
            entry["header_names"] = sorted(k.lower() for k in h.keys())
        with _LOCK, open(HITS, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _outsider_ip(self) -> str:
        """The outsider's address on the network this request came in on. The lab
        answers on redamon-network and on pentest-net at the same last octets, and
        a browser behind the capture proxy reaches only the pentest-net one."""
        local = self.connection.getsockname()[0]
        if local.count(".") == 3 and not local.startswith("127."):
            return local.rsplit(".", 1)[0] + ".96"
        return OUTSIDER

    def _send(self, status: int, body: bytes | str = b"", ctype: str = "text/html; charset=utf-8",
              headers: dict | None = None) -> None:
        data = body.encode() if isinstance(body, str) else body
        self._log(status)
        self.send_response(status)
        for k, v in {**HEADERS_COMMON, **(headers or {})}.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD" and data:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, status: int, obj, headers: dict | None = None) -> None:
        self._send(status, json.dumps(obj), "application/json", headers)

    def _stream(self, status: int, ctype: str, size: int, head: bytes, filler: bytes = b"\0") -> None:
        """A large body, honouring a `Range: bytes=0-N` request."""
        rng = self.headers.get("Range") or ""
        start, end = 0, size - 1
        if rng.startswith("bytes="):
            try:
                a, b = rng[6:].split("-", 1)
                start, end = int(a or 0), min(int(b or size - 1), size - 1)
                status = 206
            except ValueError:
                pass
        length = end - start + 1
        self._log(status)
        self.send_response(status)
        for k, v in HEADERS_COMMON.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if self.command == "HEAD":
            return
        body = head + filler * max(0, size - len(head))
        try:
            pos = start
            while pos <= end:
                chunk = body[pos:min(end + 1, pos + 65536)]
                self.wfile.write(chunk)
                pos += len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- verbs ------------------------------------------------------------------

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_OPTIONS(self):
        self._route()

    def _route(self) -> None:
        try:
            {"main": self._main, "twin": self._twin, "hostile": self._hostile,
             "outsider": self._outsider}[ROLE]()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- main -------------------------------------------------------------------

    def _main(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        authed = _authed(self.headers)
        method = self.command
        deny = lambda: self._json(401, {"error": "authentication required"})  # noqa: E731

        if method in ("POST", "PUT", "DELETE") and path != "/login":
            # A state change from a scanner is a failure the validator counts.
            return self._json(405, {"error": "method not allowed"})
        if path == "/login" and method == "POST":
            return self._send(302, "", headers={"Location": "/", "Set-Cookie": "sid=lab-user-1; Path=/; HttpOnly"})
        if path == "/":
            uploads = '<p><a href="/uploads/invoice-1001.pdf">Your invoice</a></p>' if authed else ""
            return self._send(200, LANDING.format(uploads=uploads), headers=FRAMEWORK_HEADERS)
        if path == "/static/app.js":
            return self._send(200, APP_JS.replace("OUTSIDER", self._outsider_ip()), "application/javascript")
        if path == "/openapi.json":
            return self._json(200, OPENAPI)
        if path == "/login":
            return self._send(200, "<html><head><title>Sign in</title></head><body><form method=post>"
                                   "<input name=user><input name=password type=password></form></body></html>")
        if path in ("/logout", "/account/reset"):
            return self._send(200, "<html><body>done</body></html>")
        if path == "/internal/portal":
            return self._send(200, PORTAL)
        if path == "/internal/users/export":
            if flag("close-export"):
                return deny()
            return self._json(200, USERS)
        if path == "/api/v2/reports/export":
            return self._json(200, {"report": [{"month": m, "orders": 10 + m, "region": "lab"} for m in range(1, 13)]})
        if path == "/api/v2/orders/42":
            return self._json(200, ORDER) if authed else deny()
        if path == "/api/v1/orders/42":
            return self._json(200, ORDER)
        if path in ("/api/admin/users", "/api/admin/roles", "/api/admin/audit"):
            return self._json(403, {"error": "forbidden"}) if authed else deny()
        if path == "/api/admin/export":
            if flag("close-admin-export"):
                return deny()
            return self._json(200, {"rows": [{"n": i, "ok": True} for i in range(15)]})
        if path == "/api/admin/help":
            return self._send(200, HELP)
        if path == "/api/users/me":
            if not authed:
                return deny()
            return self._json(200, {"email": "user1@lab.invalid", "name": "Lab User 1",
                                    "password_hash": "$2b$12$" + "x" * 50, "reset_token": "rt-" + "y" * 30})
        if path == "/api/me":
            return self._json(200, {"email": "user1@lab.invalid", "name": "Lab User 1"}) if authed else deny()
        if path == "/api/status":
            return self._json(200, {"ok": True})
        if path == "/uploads/invoice-1001.pdf":
            return self._send(200, b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj << /Type /Catalog >> endobj\n" + b"0" * 900,
                              "application/pdf")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if path == "/.git/config":
            return self._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
                              "text/plain")
        if path == "/.git/refs/heads/main":
            return self._send(200, GIT_HEAD + "\n", "text/plain")
        if path.startswith("/.git/objects/"):
            key = path[len("/.git/objects/"):].replace("/", "")
            if key in GIT_OBJECTS:
                return self._send(200, GIT_OBJECTS[key], "application/octet-stream")
            return self._send(404, "not found", "text/plain")
        if path == "/.env":
            body = (f"APP_ENV=lab\nDB_HOST=db.lab.invalid\nDB_USER=lab\nDB_PASSWORD={SECRETS['env_db_password']}\n"
                    f"GITHUB_TOKEN={SECRETS['github_token']}\n")
            return self._send(200, body, "text/plain")
        if path == "/web.config":
            return self._send(200, '<?xml version="1.0"?>\n<configuration><appSettings>'
                                   '<add key="mode" value="lab"/></appSettings></configuration>',
                              "application/xml")
        if path == "/config.php":
            return self._send(403, "<html><head><title>403 Forbidden</title></head><body>Forbidden</body></html>")
        if path == "/config.php.bak":
            return self._send(200, "<?php\n$db_host = 'db.lab.invalid';\n$db_name = 'lab';\n// " + "-" * 120,
                              "text/plain")
        if path == "/backup.zip":
            return self._stream(200, "application/zip", 5 * 1024 * 1024, b"PK\x03\x04\x14\x00\x00\x00")
        if path == "/actuator/env":
            return self._json(200, {"activeProfiles": ["lab"], "propertySources": [
                {"name": "server.ports", "properties": {"local.server.port": {"value": 8080}}},
                {"name": "systemEnvironment", "properties": {"PATH": {"value": "/usr/bin"},
                                                               "DB_PASSWORD": {"value": "******"}}}]})
        if path == "/actuator/heapdump":
            head = (f"JAVA PROFILE 1.0.2\0 password={SECRETS['heap_password']} {SECRETS['heap_jdbc']} "
                    f"{SECRETS['heap_aws_key']} ").encode()
            return self._stream(200, "application/octet-stream", 5 * 1024 * 1024, head)
        if path == "/debug/error":
            return self._send(500, DJANGO_DEBUG)
        if path == "/console":
            if query.get("__debugger__") == ["yes"]:
                # PIN guessing is refused: AG8 counts these.
                return self._json(403, {"error": "locked"})
            return self._send(200, WERKZEUG.format(secret=SECRETS["werkzeug_secret"]))
        if path == "/console-open":
            if query.get("__debugger__") == ["yes"]:
                ok = (query.get("cmd") == ["1+1"] and query.get("s") == [SECRETS["werkzeug_secret"]]
                      and query.get("frm") == ["0"])
                return self._send(200 if ok else 400, "2" if ok else "error", "text/plain")
            return self._send(200, WERKZEUG_OPEN.format(secret=SECRETS["werkzeug_secret"], frm="0"))
        if path == "/_ignition/health-check":
            return self._json(200, {"can_execute_commands": True, "ignition": "2.5.1"})
        if path == "/_ignition/execute-solution":
            return self._json(405, {"error": "method not allowed"})
        if path == "/phpinfo.php":
            return self._send(200, PHPINFO)
        if path in ("/admin", "/settings"):
            return self._send(302, "", headers={"Location": "/login"})
        # -- v2 rows --
        if path == "/actuator/mappings":
            return self._json(200, MAPPINGS)
        if path == "/api/internal/billing/reconcile":
            return self._json(200, {"batch": [{"invoice": 1000 + i, "state": "open", "amount": 10 * i}
                                              for i in range(8)]})
        if path in ("/api/internal/billing/close", "/api/admin/reports"):
            return deny()
        if path == "/api/orders/7":
            return self._json(200, {**ORDER, "id": 7}) if authed else deny()
        if path == "/api/orders":
            return self._json(200, [{"id": i, "item": "widget", "customer": f"user{i % 25}@lab.invalid"}
                                    for i in range(50)])
        if path in ("/admin/dashboard", "/admin/reports"):
            return self._send(200, SPA_ADMIN)
        if path == "/api/admin/stats":
            return self._json(200, {"members": 25, "orders_by_month": [30 + m for m in range(12)],
                                    "revenue_by_region": {"north": 120, "south": 80}})
        if path == "/api/profile":
            return self._profile(authed, parts.query)
        if path == "/profile":
            if not authed:
                return self._send(302, "", headers={"Location": "/login"})
            return self._send(200, f'<html><head><title>Profile</title><script src="http://{self._outsider_ip()}/widget.js">'
                                   '</script></head><body><h1>Your profile</h1><p>Name: Lab User 1</p>'
                                   '<p>Email: user1@lab.invalid</p></body></html>')
        return self._send(404, "<html><head><title>404 Not Found</title></head><body>Not found</body></html>")

    def _profile(self, authed: bool, query: str) -> None:
        """The logged-in profile: a CORS policy reflecting any Origin with credentials,
        and a shared cache that serves a stored answer to anyone for the TTL (AG16)."""
        origin = self.headers.get("Origin")
        cors = {"Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true"} if origin else {}
        now = time.time()
        with _LOCK:
            stored = _PROFILE_CACHE.get(query) if query else None
            if stored and now - stored[1] > _PROFILE_TTL:
                _PROFILE_CACHE.pop(query, None)
                stored = None
        if stored:
            return self._send(200, stored[0], "application/json",
                              {**cors, "Cache-Control": f"public, max-age={_PROFILE_TTL}",
                               "X-Cache": "HIT", "Age": str(max(1, int(now - stored[1])))})
        if not authed:
            return self._json(401, {"error": "authentication required"}, cors)
        body = json.dumps({"email": "user1@lab.invalid", "name": "Lab User 1", "role": "member",
                           "permissions": ["orders:read", "profile:write"], "plan": "lab"}).encode()
        if query:
            with _LOCK:
                _PROFILE_CACHE[query] = (body, now)
        return self._send(200, body, "application/json",
                          {**cors, "Cache-Control": f"public, max-age={_PROFILE_TTL}", "X-Cache": "MISS"})

    # -- twin -------------------------------------------------------------------

    def _twin(self) -> None:
        path = urlsplit(self.path).path
        if self.command not in ("GET", "HEAD"):
            return self._json(405, {"error": "method not allowed"})
        if path == "/":
            return self._send(200, LANDING.format(uploads=""), headers=FRAMEWORK_HEADERS)
        if path == "/static/app.js":
            return self._send(200, "// twin bundle\n", "application/javascript")
        if path == "/internal/users/export":
            return self._json(200, USERS[:5])
        if path == "/actuator/env":
            return self._json(200, {"activeProfiles": ["twin"], "propertySources": [{"name": "systemEnvironment"}]})
        return self._send(404, "<html><head><title>404 Not Found</title></head><body>Not found</body></html>")

    # -- hostile ----------------------------------------------------------------

    def _hostile(self) -> None:
        path = urlsplit(self.path).path
        if self.command not in ("GET", "HEAD"):
            return self._json(405, {"error": "method not allowed"})
        if path == "/":
            # Laravel only, so its technology set differs from main's (no cross-host here).
            return self._send(200, SPA_SHELL, headers={"Set-Cookie": "laravel_session=h; Path=/; HttpOnly"})
        if path.startswith("/spa/"):
            return self._send(200, SPA_SHELL)
        if path == "/_ignition/health-check":
            return self._json(200, {"can_execute_commands": False, "ignition": "2.5.1"})
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if path == "/.git/refs/heads/main":
            return self._send(200, BOMB_HASH + "\n", "text/plain")
        if path == f"/.git/objects/{BOMB_HASH[:2]}/{BOMB_HASH[2:]}":
            return self._send(200, GIT_BOMB, "application/octet-stream")
        if path == "/api/public-cors":
            return self._json(200, {"products": [{"sku": f"p{i}", "price": 5 + i} for i in range(8)]},
                              {"Access-Control-Allow-Origin": "*"})
        if path == "/static/hostile.js":
            return self._send(200, HOSTILE_JS.replace("OUTSIDER", self._outsider_ip()), "application/javascript")
        if path == "/openapi.json":
            return self._send(200, HOSTILE_OPENAPI, "application/json")
        if path.startswith("/api/missing/"):
            return self._json(200, {"error": "not found", "code": 404, "hint": "check the path " + "." * 40})
        if path.startswith("/wall/"):
            return self._send(302, "", headers={"Location": "/login"})
        if path == "/big":
            return self._stream(200, "text/html", 20 * 1024 * 1024, b"<html><body>", b"a")
        if path == "/slow":
            time.sleep(30)
            return self._json(200, USERS[:3])
        if path == "/redirect-internal":
            return self._send(302, "", headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        if path == "/cookie-trap":
            return self._send(200, "<html><head><title>Trap</title></head><body>" + "t" * 80 + "</body></html>",
                              headers={"Set-Cookie": "sid=trap; Path=/"})
        if path.startswith("/rate/"):
            with _LOCK:
                now = time.time()
                if now - _RATE["window"] >= 1.0:
                    _RATE["window"], _RATE["count"] = now, 0
                _RATE["count"] += 1
                over = _RATE["count"] > 3
            if over:
                return self._json(429, {"error": "slow down"}, {"Retry-After": "1"})
            return self._json(200, USERS[:4])
        if path == "/reset-conn":
            self._log(0)
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.close_connection = True
            self.connection.close()
            return None
        if path == "/xss-snippet":
            return self._send(200, "<html><head><title>Notes</title></head><body><img src=x onerror=alert(1)> "
                                   "user1@lab.invalid user2@lab.invalid user3@lab.invalid</body></html>")
        if path == "/backup.tar.gz":
            if self.command == "HEAD":
                return self._send(405, "", "text/plain")
            return self._stream(200, "application/gzip", 2 * 1024 * 1024, b"\x1f\x8b\x08\x00")
        return self._send(404, "<html><head><title>404 Not Found</title></head><body>Not found</body></html>")

    # -- outsider ---------------------------------------------------------------

    def _outsider(self) -> None:
        return self._send(200, "// outsider\n", "application/javascript")


def _serve_tls() -> None:
    cert, key = "/srv/tls/cert.pem", "/srv/tls/key.pem"
    if not (os.path.exists(cert) and os.path.exists(key)):
        return
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    class _TLSServer(ThreadingHTTPServer):
        # A wrapped listening socket handshakes inside accept(), on the one serving
        # thread, so a burst of parallel clients (httpx verify) times some out at
        # random. Handshaking in the worker thread keeps the lab deterministic.
        daemon_threads = True

        def finish_request(self, request, client_address):
            try:
                request = ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            super().finish_request(request, client_address)

    _TLSServer(("0.0.0.0", 443), Handler).serve_forever()


def main() -> None:
    open(HITS, "a").close()
    if ROLE == "hostile":
        threading.Thread(target=_serve_tls, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
