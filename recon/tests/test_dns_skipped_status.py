"""Subdomain.status when the DNS step is skipped (plan 08.1).

With DNS resolution off (resolve=False), discover_subdomains wrote every
candidate as "resolved", brute-forced guesses included, although nothing was
resolved. They are "unverified" now, the value uncover and the passive-DNS
writers already use for names nobody resolved. The readers count "resolved"
by a RESOLVES_TO edge or by status == "resolved", so an unverified name is
never counted as one.

Fixture names are under example.test only.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import domain_recon as dr  # noqa: E402
from recon.partial_recon_modules import helpers, subdomain_discovery  # noqa: E402

ROOT = "example.test"
GUESSED = ["admin.example.test", "dev.example.test", "vpn.example.test"]
PASSIVE = ["www.example.test"]


def _discover(resolve: bool, resolver=None):
    """discover_subdomains with every source stubbed and puredns switched off
    (its real early return keeps the list unchanged)."""
    with patch.object(dr, "query_crtsh", return_value={n: {"crt.sh"} for n in PASSIVE}), \
         patch.object(dr, "query_hackertarget", return_value={}), \
         patch.object(dr, "run_subfinder", return_value=set()), \
         patch.object(dr, "run_amass", return_value=set()), \
         patch.object(dr, "run_knockpy", return_value=set(GUESSED)), \
         patch.object(dr, "resolve_all_dns", side_effect=resolver or (lambda *a, **k: {})):
        return dr.discover_subdomains(ROOT, bruteforce=True, resolve=resolve,
                                      save_output=False, settings={"PUREDNS_ENABLED": False})


def test_dns_skipped_writes_every_candidate_as_unverified():
    result = _discover(resolve=False)
    assert sorted(result["subdomains"]) == sorted(GUESSED + PASSIVE)
    assert result["subdomain_status_map"] == {n: "unverified" for n in GUESSED + PASSIVE}
    assert "resolved" not in result["subdomain_status_map"].values()


def test_dns_on_still_writes_resolved_only_for_names_with_records():
    def resolver(domain, subs, **kw):
        return {"domain": {"has_records": True},
                "subdomains": {n: {"has_records": n == "www.example.test",
                                   "ips": {"ipv4": ["192.0.2.10"] if n == "www.example.test" else [],
                                           "ipv6": []},
                                   "records": {}}
                               for n in subs}}

    result = _discover(resolve=True, resolver=resolver)
    assert result["subdomain_status_map"] == {"www.example.test": "resolved"}


def test_the_pipeline_merge_keeps_unverified_for_discovered_names():
    """main.merge_group_hosts hands the domain writer discovery's status map:
    an unverified name stays unverified, and DNS off adds no resolution."""
    from recon import main as recon_main

    discovery = {"subdomains": GUESSED + PASSIVE, "dns": {},
                 "subdomain_status_map": {n: "unverified" for n in GUESSED + PASSIVE}}
    merged = recon_main.merge_group_hosts(
        discovery, {"include_root_domain": False, "full_subdomains": []}, ROOT, {}, False)
    assert merged["status_map"] == {n: "unverified" for n in GUESSED + PASSIVE}


# --------------------------------------------------------------------------- #
# Partial subdomain discovery: the same statuses reach its graph writer
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)


@pytest.fixture
def graph(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_partial_discovery.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    return client


def _partial(result, user_inputs=(), resolver=None):
    cfg = {"_settings": {}, "domains": [ROOT], "domain": ROOT, "batch_mode": False,
           "domain_groups": [{"rootDomain": ROOT, "prefixes": ["*"], "batch": False}],
           "user_inputs": list(user_inputs)}
    with patch("recon.main_recon_modules.domain_recon.discover_subdomains", return_value=result), \
         patch("recon.main_recon_modules.domain_recon.run_puredns_resolve",
               side_effect=lambda subs, domain, s: (list(subs), "filtered")), \
         patch("recon.main_recon_modules.domain_recon.resolve_all_dns",
               side_effect=resolver or (lambda *a, **k: {})):
        subdomain_discovery.run_subdomain_discovery(cfg)


def _written(graph):
    return graph.update_graph_from_partial_discovery.call_args.kwargs["recon_data"]


def test_partial_discovery_writes_the_unverified_status_it_was_given(graph):
    names = GUESSED + PASSIVE
    _partial({"domain": ROOT, "subdomains": list(names), "subdomain_count": len(names),
              "dns": {}, "external_domains": [],
              "subdomain_status_map": {n: "unverified" for n in names}})
    assert _written(graph)["subdomain_status_map"] == {n: "unverified" for n in names}


def test_partial_re_resolution_never_marks_an_unanswered_name_resolved(graph):
    """A user-typed name triggers a second DNS pass; only a name with records
    becomes "resolved", one that did not answer gets no status at all."""
    def resolver(domain, subs, **kw):
        return {"domain": {}, "subdomains": {
            n: {"has_records": n == "new.example.test",
                "ips": {"ipv4": ["192.0.2.20"] if n == "new.example.test" else [], "ipv6": []}}
            for n in subs}}

    _partial({"domain": ROOT, "subdomains": ["admin.example.test"], "subdomain_count": 1,
              "dns": {}, "external_domains": [], "subdomain_status_map": {}},
             user_inputs=["new.example.test", "gone.example.test"], resolver=resolver)
    status = _written(graph)["subdomain_status_map"]
    assert status == {"new.example.test": "resolved"}
    # The second puredns pass (plan 08.2) reports how the list was filtered.
    assert _written(graph)["metadata"]["wildcard_filter"] == "filtered"
