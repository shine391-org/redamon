"""F02 request-shape round-trip contracts (offline, no target traffic)."""
import importlib.util
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("target_helpers_f02", ROOT / "helpers" / "target_helpers.py")
th = importlib.util.module_from_spec(spec)
spec.loader.exec_module(th)


def _url(params, **extra):
    return th._endpoint_url("https://api.example.test", "/search", {"parameters": {"query": params}, **extra})


def test_openapi_encoded_sample_is_not_double_encoded():
    url = _url([{"name": "q", "sample_values": ["a%20b"], "sample_values_encoding": "percent-encoded"}])
    assert url == "https://api.example.test/search?q=a%20b"
    assert parse_qsl(urlsplit(url).query, keep_blank_values=True) == [("q", "a b")]


def test_decoded_observation_round_trips_reserved_and_unicode_values():
    value = "a&b=# %+雪"
    url = _url([{"name": "q", "sample_values": [value]}])
    assert parse_qsl(urlsplit(url).query, keep_blank_values=True) == [("q", value)]


def test_empty_duplicate_case_and_order_are_preserved():
    params = [
        {"name": "k", "sample_values": ["1"]},
        {"name": "k", "sample_values": ["2"]},
        {"name": "empty", "sample_values": [""]},
        {"name": "K", "sample_values": ["3"]},
    ]
    url = _url(params)
    assert parse_qsl(urlsplit(url).query, keep_blank_values=True) == [
        ("k", "1"), ("k", "2"), ("empty", ""), ("K", "3")]


def test_lost_graph_shape_is_marked_fidelity_unknown():
    endpoint = {"parameters": {"query": [{"name": "k", "sample_values": ["1"]}]},
                "fidelity_unknown": True}
    url = th._endpoint_url("https://api.example.test", "/search", endpoint)
    assert url.endswith("?k=1")
    assert endpoint["fidelity"] == ["fidelity_unknown"]


def test_raw_control_observation_is_refused_without_fabricated_recovery():
    url = th._endpoint_url("https://api.example.test", "/search", {
        "parameters": {"query": [{"name": "q", "sample_values": ["x\ny"]}]}})
    assert url is None


def test_legacy_name_keyed_projection_is_accepted_without_invented_values():
    url = th._endpoint_url("https://api.example.test", "/search", {
        "parameters": {"q": {"sample_values": ["a&b"]}}})
    assert parse_qsl(urlsplit(url).query, keep_blank_values=True) == [("q", "a&b")]


def test_full_and_partial_use_the_same_observation_contract():
    observation = [{"name": "q", "sample_values": ["a&b=# %+雪"]}]
    full = _url(observation)
    partial = _url(observation)
    assert parse_qsl(urlsplit(full).query, keep_blank_values=True) == parse_qsl(
        urlsplit(partial).query, keep_blank_values=True)


def test_body_and_path_parameters_are_not_promoted_to_query():
    endpoint = {"parameters": {"query": [], "body": [{"name": "token", "sample_values": ["x"]}],
                                "path": [{"name": "id", "sample_values": ["7"]}]}}
    assert th._endpoint_url("https://api.example.test", "/items", endpoint) == "https://api.example.test/items"


def test_base_negative_control_captures_old_double_encoding_defect():
    # The pinned base had no producer marker and therefore quoted this token
    # again. Keep the control executable without weakening the candidate path.
    old_url = "https://api.example.test/search?q=" + quote("a%20b", safe="")
    assert old_url.endswith("q=a%2520b")
    assert parse_qsl(urlsplit(old_url).query) == [("q", "a%20b")]
