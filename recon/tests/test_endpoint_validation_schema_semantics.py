"""F05 schema meaning, not just generated freshness/property membership.

Keep the canonical text, generated body, structured property and actual renderer
honest independently: regeneration once restored the obsolete drop/dead claim.
This file can be overlaid unchanged on the pinned pre-fix tree as a control.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    path = ROOT / "graph_db" / f"{name}.py"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = _load("schema_catalog")
renderer = _load("schema_render")
endpoint = catalog.LABELS["Endpoint"]
properties = {
    prop["name"]: prop
    for group in endpoint["groups"]
    for prop in group["properties"]
}


def _endpoint_block(text):
    match = re.search(r"^\*\*Endpoint\*\* -.*?(?=^\*\*[A-Z]|\Z)", text, re.M | re.S)
    assert match is not None, "Endpoint label block missing"
    return match.group()


def _status_line(text):
    return next(line for line in text.splitlines() if "validation_status (string):" in line)


VIEWS = {
    "canonical": _status_line(_endpoint_block((ROOT / "graph_db/schema_sections.md").read_text())),
    "generated_body": _status_line(endpoint["body"]),
    "structured_property": properties["validation_status"]["desc"],
    "rendered_endpoint": _status_line(_endpoint_block(renderer.render_schema())),
}


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize("required", [
    '"hittable" is the only verified state',
    '"not_hittable" is a retained negative observation',
    'including 404), not proof that the route is dead',
    '"catch_all" is a retained catch_all_like observation',
    '"unknown" is a retained inconclusive observation after a timeout or transport error',
    'exception class in validation_error; unknown is not dead',
    '"unvalidated" means no endpoint probe was performed',
    '"skipped_unknown" is a validation_error reason on "unvalidated", not a separate validation_status',
    "retained subject to graph ingestion's path/base URL and scope guards",
    'must filter validation_status = "hittable"',
])
def test_validation_meaning_survives_every_projection(view, required):
    assert required in VIEWS[view], f"{view}: missing semantic contract: {required}"


@pytest.mark.parametrize("view", VIEWS)
def test_obsolete_drop_and_dead_claims_do_not_return(view):
    text = VIEWS[view]
    for contradiction in ('never written', 'endpoint is dropped', '"not_hittable" (dead)'):
        assert contradiction not in text, f"{view}: obsolete contradiction: {contradiction}"


def test_validation_error_is_described_even_when_validation_is_disabled():
    canonical = _endpoint_block((ROOT / "graph_db/schema_sections.md").read_text())
    rendered = _endpoint_block(renderer.render_schema())
    for text in (canonical, endpoint["body"], rendered):
        line = next(line for line in text.splitlines() if "validation_error (string):" in line)
        assert "including when JS_RECON_VALIDATE_ENDPOINTS is off" in line
        assert '"skipped_unknown"' in line
        assert "exception type name" in line
    assert "including when JS_RECON_VALIDATE_ENDPOINTS is off" in properties["validation_error"]["desc"]
