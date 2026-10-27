"""The Firebase Realtime Database validator (recon/helpers/js_recon/validators.py).

An anonymous `/.json?shallow=true` read that answers 200 means the database is
publicly readable. A 401 or 403 means the rules refused the read: the protection
works. Reporting the refusal as `valid: True` stored the finding as
'validated', which the Priority Board reads as proof and ranks "Act now".
"""
from __future__ import annotations

import json
from unittest import mock

import pytest

from recon.helpers.js_recon import validators

DB = "https://example-demo-1a2b3.firebaseio.com"


@pytest.fixture(autouse=True)
def _no_pacing():
    with mock.patch.object(validators.time, "sleep"):
        yield


def _answer(status):
    resp = mock.MagicMock(status_code=status)
    with mock.patch.object(validators.requests, "get", return_value=resp) as get:
        result = validators.validate_firebase(f'databaseURL:"{DB}"')
    return result, get


def test_a_publicly_readable_database_is_valid():
    result, get = _answer(200)
    assert result["valid"] is True
    assert result["scope"] == "database"
    assert get.call_args.args[0] == f"{DB}/.json?shallow=true"


@pytest.mark.parametrize("status", [401, 403])
def test_a_locked_database_is_not_valid(status):
    result, _ = _answer(status)
    assert result["valid"] is False
    assert "locked" in result["info"].lower()
    assert f"status={status}" in result["info"]
    assert result["error"] == ""


def test_a_401_carries_what_the_score_model_reads_as_a_rejection():
    # score_model._validator_rejected_it: status 'invalid', no error, status=401.
    result, _ = _answer(401)
    assert result["error"] == ""
    assert "status=401" in result["info"]


def test_other_answers_are_unchanged():
    result, _ = _answer(404)
    assert result == {"valid": False, "state": "unknown", "scope": "", "info": "status=404", "error": ""}


def test_js_recon_stores_a_locked_database_as_rejected_not_validated():
    """The shape js_recon writes from the validator's answer: the database's
    own 401 is 'rejected' (plan 05.7), never 'validated'."""
    from recon.main_recon_modules import js_recon

    secret = {"name": "Firebase URL", "matched_text": DB, "confidence": "high",
              "validator_ref": "validate_firebase", "source_url": "http://192.0.2.10/app.js"}
    resp = mock.MagicMock(status_code=401)
    with mock.patch.object(validators.requests, "get", return_value=resp):
        js_recon._validate_secrets([secret], {"JS_RECON_VALIDATE_KEYS": True,
                                              "JS_RECON_VALIDATION_TIMEOUT": 5})
    assert secret["validation"]["status"] == "rejected"
    assert "status=401" in json.dumps(secret["validation"])
