"""Named normalizers: one rule field derived from one or more node properties.

The writers disagree on names (`cvss_score` vs `cvss`, `name` vs `title`) and on
shapes (a CVE can sit in `cves`, `cve_ids`, `cve_id`, `aliases`, or be the node's
own `id`), so a rule field that means one thing reads through one of these.

Standalone on purpose: stdlib only, no package-relative import, so build.py can
load it on a host with no neo4j driver to check the catalog's normalizer names.

Each entry is `name -> (function, inputs)`. `inputs` is the tuple of
properties the normalizer reads, which the sweep projects; `None` means it
reads the single property the field names in `from`.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_CVE = re.compile(r"CVE-(\d{4})-(\d{4,})", re.IGNORECASE)
_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def severity(props: dict, _source=None):
    value = _text(props.get("severity"))
    return value.lower() if value else None


def cvss(props: dict, _source=None):
    for key in ("cvss_score", "cvss"):
        value = props.get(key)
        if value is None or isinstance(value, bool):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _cve_strings(props: dict):
    for key in ("cves", "cve_ids", "aliases"):
        items = props.get(key)
        if isinstance(items, str):
            items = [items]
        for item in items or []:
            if item:
                yield str(item)
    if props.get("cve_id"):
        yield str(props["cve_id"])
    # Netlas keys its nodes on the CVE itself. The Shodan-family ids embed a CVE
    # between a prefix and an IP, which the anchored match deliberately misses.
    node_id = props.get("id")
    if node_id and _CVE_EXACT.match(str(node_id)):
        yield str(node_id)


def cve_ids(props: dict, _source=None):
    found = set()
    for text in _cve_strings(props):
        for year, num in _CVE.findall(text):
            found.add(f"CVE-{year}-{num}")
    return sorted(found)


def _newest(props: dict):
    best = None
    for cve in cve_ids(props):
        m = _CVE.match(cve)
        key = (int(m.group(1)), int(m.group(2)))
        if best is None or key > best[0]:
            best = (key, cve)
    return best


def has_cve(props: dict, _source=None):
    return bool(cve_ids(props))


def cve_year(props: dict, _source=None):
    best = _newest(props)
    return best[0][0] if best else None


def name(props: dict, _source=None):
    return _text(props.get("name")) or _text(props.get("title"))


def port_from_url(props: dict, source=None):
    raw = _text(props.get(source)) if source else None
    if not raw:
        return None
    try:
        parts = urlsplit(raw if "://" in raw else f"//{raw}")
        if parts.port is not None:
            return parts.port
        return _DEFAULT_PORTS.get((parts.scheme or "").lower())
    except ValueError:
        return None


def advisory_prefix(props: dict, source=None):
    raw = _text(props.get(source)) if source else None
    if not raw:
        return None
    head = raw.split("-", 1)[0].strip()
    return head.upper() or None


def present(props: dict, source=None):
    return _text(props.get(source)) is not None if source else False


#: Keys that are public by design. score_model.PUBLIC_CLIENT_KEY_TYPES, which
#: this standalone module cannot import; a test pins the two equal.
PUBLIC_CLIENT_KEY_TYPES = frozenset({
    "gcp api key", "gcpkey", "firebase api key", "segment write key",
    "amplitude api key", "new relic browser api token", "sentry dsn",
    "stripe publishable key", "google recaptcha key", "mapbox token",
    "algolia app id", "algolia search key", "intercom app id", "pusher key",
    "clerk publishable key", "mailgun public key", "flutterwave public key",
    "supabase anon key", "supabase publishable key",
})


def public_client_key(props: dict, _source=None):
    """The flag js_recon writes, or, on a node written before it, a pattern
    name every reader calls public."""
    if props.get("public_client_key") is True:
        return True
    secret_type = _text(props.get("secret_type"))
    return bool(secret_type) and secret_type.lower() in PUBLIC_CLIENT_KEY_TYPES


_CVE_INPUTS = ("cves", "cve_ids", "cve_id", "aliases", "id")

NORMALIZERS = {
    "severity": (severity, ("severity",)),
    "cvss": (cvss, ("cvss_score", "cvss")),
    "cve_ids": (cve_ids, _CVE_INPUTS),
    "has_cve": (has_cve, _CVE_INPUTS),
    "cve_year": (cve_year, _CVE_INPUTS),
    "name": (name, ("name", "title")),
    "port_from_url": (port_from_url, None),
    "advisory_prefix": (advisory_prefix, None),
    "present": (present, None),
    "public_client_key": (public_client_key, ("public_client_key", "secret_type")),
}


def inputs_of(field: dict) -> tuple:
    """The properties one catalog field reads, whether directly or through a normalizer."""
    if field.get("normalizer"):
        _fn, inputs = NORMALIZERS[field["normalizer"]]
        return tuple(inputs) if inputs is not None else (field["from"],)
    return (field["prop"],)


def field_value(field: dict, props: dict):
    """The value one catalog field has on a node, from its projected properties."""
    normalizer = field.get("normalizer")
    if normalizer:
        fn, _inputs = NORMALIZERS[normalizer]
        return fn(props, field.get("from"))
    return props.get(field["prop"])
