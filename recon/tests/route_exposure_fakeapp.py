"""A loopback HTTP app for the route exposure tests.

Routes are exact paths or prefixes ending in `*`; each answers a tuple
(status, headers, body) or a callable taking the Request and returning one.
Every request is recorded (method, path, which auth headers rode on it, Range),
so a test asserts the requests the scanner BUILT, not only its verdicts.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Union

Answer = Union[tuple, Callable]


@dataclass
class Hit:
    method: str
    path: str
    headers: dict = field(default_factory=dict)
    at: float = field(default_factory=time.time)

    @property
    def authed(self) -> bool:
        return any(h in self.headers for h in ("authorization", "cookie", "x-api-key"))


class FakeApp:
    def __init__(self, routes: dict, default: tuple = (404, {"Content-Type": "text/html"},
                                                         b"<html><title>404 Not Found</title>"
                                                         b"<body>" + b"missing " * 20 + b"</body></html>"),
                 host: str = "127.0.0.1"):
        self.routes = dict(routes)
        self.default = default
        self.hits: list = []
        self._lock = threading.Lock()
        app = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _answer(self, with_body: bool):
                hit = Hit(self.command, self.path, {k.lower(): v for k, v in self.headers.items()})
                with app._lock:
                    app.hits.append(hit)
                answer = app.lookup(self.path)
                if callable(answer):
                    answer = answer(hit)
                if answer == "RESET":
                    self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                               b"\x01\x00\x00\x00\x00\x00\x00\x00")
                    self.close_connection = True
                    self.connection.close()
                    return
                status, headers, body = answer
                if callable(body):
                    self._stream(status, headers, body, with_body)
                    return
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if with_body:
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def _stream(self, status, headers, generator, with_body):
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if not with_body:
                    return
                try:
                    for chunk in generator():
                        self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

            def do_GET(self):
                self._answer(True)

            def do_HEAD(self):
                self._answer(False)

            def do_POST(self):
                self._answer(True)

            def do_DELETE(self):
                self._answer(True)

        self.host = host
        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.server.server_address[1]}"

    def lookup(self, path: str):
        bare = path.split("?", 1)[0]
        if bare in self.routes:
            return self.routes[bare]
        for key, answer in self.routes.items():
            if key.endswith("*") and bare.startswith(key[:-1]):
                return answer
        return self.default

    def paths(self, method: str | None = None) -> list:
        return [h.path for h in self.hits if method is None or h.method == method]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def json_answer(status: int, body: bytes, **headers) -> tuple:
    return status, {"Content-Type": "application/json", **headers}, body


def html_answer(status: int, body: bytes, **headers) -> tuple:
    return status, {"Content-Type": "text/html", **headers}, body


def slow(seconds: float, answer: tuple) -> Callable:
    def handler(_hit):
        time.sleep(seconds)
        return answer
    return handler


def corpus(base: str, *, endpoints: dict | None = None, js: list | None = None,
           technologies: list | None = None, ip: str = "127.0.0.1") -> dict:
    """A combined_result for an IP-mode run on one loopback address."""
    return {
        "metadata": {"expanded_ips": [ip], "modules_executed": []},
        "subdomains": [],
        "http_probe": {"by_url": {base: {"url": base, "status_code": 200,
                                         "technologies": technologies or []}}},
        "resource_enum": {"by_base_url": {base: {"endpoints": endpoints or {}}}},
        "js_recon": {"endpoints": [
            {"type": "rest", "method": "GET", "path": p, "full_url": p,
             "source_js": base + "/static/app.js", "category": "endpoint"} for p in (js or [])]},
    }


def settings(**overrides) -> dict:
    base = {"ROUTE_EXPOSURE_ENABLED": True, "IP_MODE": True, "TARGET_IPS": ["127.0.0.1"],
            "ROUTE_EXPOSURE_MAX_RPS": 50, "ROUTE_EXPOSURE_WORKERS": 4, "ROUTE_EXPOSURE_TIMEOUT": 5,
            "ROUTE_EXPOSURE_SEED_PATHS": False, "ROUTE_EXPOSURE_VCS_FILES": False,
            "ROUTE_EXPOSURE_BACKUP_FILES": False, "ROUTE_EXPOSURE_VERSION_VARIANTS": False,
            "ROUTE_EXPOSURE_COMPARE_LOGGED_IN": True, "ROUTE_EXPOSURE_PII_DETECTION": True,
            # v2 generators and riders off by default in tests; each v2 test opts its own in.
            "ROUTE_EXPOSURE_SIBLINGS": False, "ROUTE_EXPOSURE_FRAMEWORK_SEEDS": False,
            "ROUTE_EXPOSURE_FOLLOW_CATALOGS": False, "ROUTE_EXPOSURE_GIT_WALK": False,
            "ROUTE_EXPOSURE_CROSS_HOST": False, "ROUTE_EXPOSURE_CORS_RIDER": False,
            "ROUTE_EXPOSURE_CACHE_RIDER": False}
    base.update(overrides)
    return base


BEARER = {"authType": "bearer", "authValue": "lab-token"}
COOKIE = {"authType": "cookie", "authValue": "sid=lab-user-1"}
HEADER = {"authType": "header", "authValue": "lab-key", "authHeaderName": "X-API-Key"}
