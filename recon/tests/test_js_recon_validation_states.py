"""What a secret validator learned, kept apart from what it could not learn (plan 05.7).

Every validator answered {'valid': False} for any non-2xx, and js_recon stored
all of them, timeouts and breaker skips included, as 'invalid'. A validator
now returns an explicit `state`:
  valid           the provider accepted the credential;
  rejected        the provider said it is not accepted (a 401, or the
                  provider's own "invalid key" answer);
  unknown         no verdict: a timeout, a 429 or 5xx, a network error, a
                  breaker skip, or a 403 (often a live key missing a scope);
  format_invalid  the value is not a well-formed credential.
and js_recon stores validated | rejected | unknown | format_invalid |
unvalidated (no validator) | skipped. Every key here is synthetic.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.js_recon import validators
from recon.main_recon_modules import js_recon


@pytest.fixture(autouse=True)
def _isolated():
    cb.reset_registry()
    with mock.patch.object(validators.time, "sleep"):
        yield
    cb.reset_registry()


GH = "ghp_" + "r8Tq2LmZ7xKp4Wn9Yc3Vb6Hd1Jf5Gs0Ae2Ui"

#: (validator, a matched text it accepts, the HTTP method it calls, a 200 body)
HTTP_VALIDATORS = [
    ("validate_github", GH, "get", {"login": "x"}),
    ("validate_gitlab", "glpat-" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd", "get", {"username": "x"}),
    ("validate_slack", "xoxb-1234567890-1234567890-Qx7Lm2Rt9Wn4", "post", {"ok": True}),
    ("validate_stripe", "sk_live_" + "4fT9qZ2mX7cV1bN8kL3pR6sW", "get", {"id": "acct"}),
    ("validate_google_maps", "AIza" + "Sy8Kq2Lm7Zx4Wp9Rt1Vb6Nc3Hd5Jf0Gs2Ue", "get", {"status": "OK"}),
    ("validate_sendgrid", "SG." + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3J" + "." + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4Pz7Nb3Wq", "get", {"scopes": []}),
    ("validate_mailgun", "key-" + "8d2f6b0a4c9e1f7b3d5a8c2e6f0b4d9a", "get", {"items": []}),
    ("validate_mailchimp", "9f3c1a7e5b2d8f40c6e1a9b3d7f2c5e8-us12", "get", {}),
    ("validate_hubspot", "hubspot:'4e9a1c7f-3b5d-8e2a-6c0f-9b1d7e3a5c8f'", "get", {"portalId": 1}),
    ("validate_heroku", "heroku 4e9a1c7f-3b5d-8e2a-6c0f-9b1d7e3a5c8f", "get", {"email": "x"}),
    ("validate_digitalocean", "dop_v1_" + "4e9a1c7f3b5d8e2a6c0f9b1d7e3a5c8f" * 2, "get", {"account": {}}),
    ("validate_telegram", "123456789:AA" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2K", "get", {"ok": True, "result": {}}),
    ("validate_discord", "M" + "Tk4NzY1NDMyMTAxMjM0NTY3OD" + ".Gx7Lm2" + "." + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0", "get", {"username": "x"}),
    ("validate_postmark", "4e9a1c7f-3b5d-8e2a-6c0f-9b1d7e3a5c8f", "get", {"Name": "x"}),
    ("validate_cloudflare", 'cf="' + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4Pz" + '"', "get", {"success": True, "result": {}}),
    ("validate_openai", "sk-proj-" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4Pz7Nb3" * 2, "get", {"data": []}),
]
IDS = [v[0] for v in HTTP_VALIDATORS]


def _call(name, text, method, status, body=None, exc=None):
    resp = mock.MagicMock(status_code=status)
    resp.json.return_value = body if body is not None else {}
    kwargs = {"side_effect": exc} if exc else {"return_value": resp}
    with mock.patch.object(validators.requests, method, **kwargs):
        return getattr(validators, name)(text)


@pytest.mark.parametrize("name,text,method,body", HTTP_VALIDATORS, ids=IDS)
def test_a_200_is_valid(name, text, method, body):
    assert _call(name, text, method, 200, body)["state"] == "valid"


@pytest.mark.parametrize("name,text,method,body", HTTP_VALIDATORS, ids=IDS)
def test_a_401_is_rejected(name, text, method, body):
    result = _call(name, text, method, 401)
    assert (result["valid"], result["state"]) == (False, "rejected")


@pytest.mark.parametrize("status", [403, 429, 500, 503])
@pytest.mark.parametrize("name,text,method,body", HTTP_VALIDATORS, ids=IDS)
def test_no_verdict_is_unknown(name, text, method, body, status):
    assert _call(name, text, method, status)["state"] == "unknown"


@pytest.mark.parametrize("exc", [requests.Timeout("slow"), requests.ConnectionError("down")])
@pytest.mark.parametrize("name,text,method,body", HTTP_VALIDATORS, ids=IDS)
def test_a_timeout_or_network_error_is_unknown(name, text, method, body, exc):
    result = _call(name, text, method, 0, exc=exc)
    assert (result["valid"], result["state"]) == (False, "unknown")


def test_a_breaker_skip_is_unknown():
    with mock.patch.object(validators.requests, "get", side_effect=requests.Timeout("x")):
        for _ in range(3):
            validators.validate_github(GH)
        skipped = validators.validate_github(GH)
    assert skipped["error"].startswith("skipped")
    assert skipped["state"] == "unknown"


class TestProviderAnswers:
    def test_slack_says_invalid_auth_in_a_200(self):
        for error in ("invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired"):
            assert _call("validate_slack", HTTP_VALIDATORS[2][1], "post", 200,
                         {"ok": False, "error": error})["state"] == "rejected"

    def test_slack_other_errors_are_unknown(self):
        assert _call("validate_slack", HTTP_VALIDATORS[2][1], "post", 200,
                     {"ok": False, "error": "ratelimited"})["state"] == "unknown"

    def test_google_names_an_invalid_key(self):
        key = HTTP_VALIDATORS[4][1]
        result = _call("validate_google_maps", key, "get", 200,
                       {"status": "REQUEST_DENIED", "error_message": "The provided API key is invalid."})
        assert result["state"] == "rejected"

    def test_google_denying_one_api_is_no_verdict_on_the_key(self):
        key = HTTP_VALIDATORS[4][1]
        for body in ({"status": "REQUEST_DENIED", "error_message": "This API project is not authorized to use this API."},
                     {"status": "OVER_QUERY_LIMIT"}):
            assert _call("validate_google_maps", key, "get", 200, body)["state"] == "unknown"

    def test_telegram_ok_false_in_a_200_is_unknown(self):
        assert _call("validate_telegram", HTTP_VALIDATORS[11][1], "get", 200, {"ok": False})["state"] == "unknown"

    def test_cloudflare_success_false_in_a_200_is_unknown(self):
        assert _call("validate_cloudflare", HTTP_VALIDATORS[14][1], "get", 200, {"success": False})["state"] == "unknown"

    def test_a_locked_firebase_database(self):
        db = 'databaseURL:"https://example-demo-1a2b3.firebaseio.com"'
        assert _call("validate_firebase", db, "get", 200)["state"] == "valid"
        assert _call("validate_firebase", db, "get", 401)["state"] == "rejected"
        # A 403 is as often a rule on the caller as a locked database: no verdict.
        assert _call("validate_firebase", db, "get", 403)["state"] == "unknown"


class TestNoCallValidators:
    def test_a_malformed_value_is_format_invalid(self):
        assert validators.validate_twilio_format("AC" + "a" * 32)["state"] == "format_invalid"
        assert validators.validate_twitter_format("AAAAAAAAAAAAAAAAAAAAAA" + "ab" * 10)["state"] == "format_invalid"

    def test_a_well_formed_value_is_still_unknown(self):
        r = validators.validate_twilio_format("AC" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui")
        assert (r["error"], r["state"]) == ("format_only", "unknown")

    def test_an_incomplete_credential_is_unknown(self):
        r = validators.validate_aws("AKIA" + "Q7R2M9X4K1T8B3V6")
        assert (r["error"], r["state"]) == ("incomplete_credentials", "unknown")

    def test_no_validator_is_unknown(self):
        r = validators.validate_secret("X", "y", validator_ref=None)
        assert (r["error"], r["state"]) == ("no_validator", "unknown")


# ---------------------------------------------------------------------------
# js_recon stores the state
# ---------------------------------------------------------------------------
def _validated(result, **secret):
    s = {"name": "GitHub Token Classic", "matched_text": GH, "validator_ref": "validate_github",
         "confidence": "high", **secret}
    with mock.patch.object(js_recon, "validate_secret", return_value=result):
        js_recon._validate_secrets([s], {"JS_RECON_VALIDATE_KEYS": True})
    return s["validation"]


class TestJsReconStoresTheState:
    def test_valid_is_validated(self):
        v = _validated({"valid": True, "state": "valid", "scope": "repo", "info": "user=x", "error": ""})
        assert v["status"] == "validated" and v["checked_at"]

    def test_rejected(self):
        v = _validated({"valid": False, "state": "rejected", "scope": "", "info": "status=401", "error": ""})
        assert (v["status"], v["info"]) == ("rejected", "status=401")
        assert v["checked_at"]

    def test_unknown_is_never_stored_as_invalid(self):
        for result in ({"valid": False, "state": "unknown", "scope": "", "info": "", "error": "timeout"},
                       {"valid": False, "state": "unknown", "scope": "", "info": "status=503", "error": ""},
                       {"valid": False, "state": "unknown", "scope": "", "info": "", "error": "skipped (open)"}):
            v = _validated(result)
            assert v["status"] == "unknown", result
            assert v["error"] == result["error"]

    def test_format_invalid(self):
        v = _validated({"valid": False, "state": "format_invalid", "scope": "", "info": "x",
                        "error": "format_invalid"})
        assert v["status"] == "format_invalid"

    def test_the_other_statuses_are_unchanged(self):
        assert _validated({"valid": False, "state": "unknown", "error": "no_validator"})["status"] == "unvalidated"
        assert _validated({"valid": False, "state": "unknown", "error": "incomplete_credentials"})["status"] == "incomplete"
        assert _validated({"valid": False, "state": "unknown", "error": "format_only"})["status"] == "format_validated"
        assert _validated({}, confidence="low")["status"] == "skipped"
        assert _validated({}, validator_ref=None)["status"] == "unvalidated"

    def test_a_validator_that_raises_is_unknown(self):
        s = {"name": "x", "matched_text": GH, "validator_ref": "validate_github", "confidence": "high"}
        with mock.patch.object(js_recon, "validate_secret", side_effect=RuntimeError("boom")):
            js_recon._validate_secrets([s], {"JS_RECON_VALIDATE_KEYS": True})
        assert s["validation"]["status"] == "unknown"

    def test_validation_switched_off_is_skipped(self):
        s = {"name": "x", "matched_text": GH, "validator_ref": "validate_github", "confidence": "high"}
        js_recon._validate_secrets([s], {"JS_RECON_VALIDATE_KEYS": False})
        assert s["validation"] == {"status": "skipped"}

    def test_the_summary_counts_each_state(self):
        secrets = [{"validation": {"status": st}} for st in
                   ("validated", "rejected", "unknown", "unknown", "format_invalid", "unvalidated", "skipped")]
        counts = js_recon._build_summary({"secrets": secrets})["validated_keys"]
        assert counts["live"] == 1 and counts["rejected"] == 1 and counts["unknown"] == 2
        assert counts["format_invalid"] == 1 and counts["unvalidated"] == 1 and counts["skipped"] == 1
        assert "invalid" not in counts
