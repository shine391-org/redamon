"""Which URLs are JavaScript, and which downloaded bodies really are.

One detector for js_recon, jsluice and the crawlers' JS hand-off, so the three
never disagree about what a JS file is.
"""

import re
from urllib.parse import urlparse

# The extension may carry a cache-busting suffix the server still maps to the
# file (app.js__v_3fa2, bundle.mjs~1, main.js-1a2b). The query string is not
# part of the path, so app.js?v=12 matches too.
_JS_EXTENSION = re.compile(r'\.(?:m?jsx?|tsx?)(?:[_~.\-]|$)')
# A name whose suffix is itself another file type is that type: app.js.map is
# a source map, app.js.gz an archive.
_OTHER_FILE_TYPE = re.compile(
    r'\.(?:map|json|html?|css|txt|xml|gz|br|zip|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot)$')
# Extensionless scripts served from a JS directory (/js/loader). Only a
# JavaScript Content-Type confirms them at download time.
_JS_DIRECTORIES = ('/js/', '/javascript/')

_HTML_START = re.compile(r'<(?:!doctype\s+html|html|head|body|title|meta)\b', re.IGNORECASE)


def js_url_kind(url) -> str:
    """``'extension'`` when the file name says JS, ``'directory'`` for an
    extensionless name under a JS directory, ``''`` otherwise."""
    if not isinstance(url, str) or not url:
        return ''
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return ''
    name = path.rsplit('/', 1)[-1]
    if not name:
        return ''
    if _JS_EXTENSION.search(name):
        return '' if _OTHER_FILE_TYPE.search(name) else 'extension'
    if '.' not in name and any(d in path for d in _JS_DIRECTORIES):
        return 'directory'
    return ''


def is_js_url(url) -> bool:
    return bool(js_url_kind(url))


def is_js_content_type(content_type) -> bool:
    """A JavaScript or ECMAScript media type (parameters ignored)."""
    if not isinstance(content_type, str):
        return False
    media = content_type.split(';', 1)[0].strip().lower()
    return 'javascript' in media or 'ecmascript' in media


def looks_like_html(body) -> bool:
    """The body is an HTML page: no script starts with a document tag."""
    if isinstance(body, (bytes, bytearray)):
        body = body[:1024].decode('utf-8', 'replace')
    if not isinstance(body, str):
        return False
    head = body[:1024].lstrip('﻿').lstrip()
    return head.startswith('<') and bool(_HTML_START.search(head[:512]))


def accept_js_response(url: str, content_type, body) -> tuple:
    """``(True, '')`` when a 200 answer for ``url`` is a JS file worth
    analyzing, else ``(False, reason)``.

    A single-page app answers a missing ``.js`` with its HTML shell and a 200,
    whatever the label says, so an HTML body is never JS. A JavaScript type
    is accepted on any URL; otherwise only a URL whose name says JS is (S3 and
    CDNs serve bundles as application/octet-stream or text/plain).
    """
    if looks_like_html(body):
        return False, 'html'
    if is_js_content_type(content_type):
        return True, ''
    media = (content_type or '').split(';', 1)[0].strip().lower() if isinstance(content_type, str) else ''
    if 'html' in media:
        return False, 'html'
    if js_url_kind(url) == 'extension':
        return True, ''
    return False, 'not_js'
