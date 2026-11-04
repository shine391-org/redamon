"""Route exposure triage: tiers, classes, review skip and grouping (plan §8).

A pending lead sits at the T4 floor until a proof-typed CONFIRMS edge promotes
it; a signature finding is classed by its vulnerability_type, read from the
fixed projection the scorer actually gets (never exposure_kind), and the same
exposed path across hosts is one fix.
"""

import re
import unittest

import agentic.cypherfix_triage.score_model as sm
from agentic.cypherfix_triage import evidence, fact_queries, grouping

ROUTE_TYPES = {
    "unauthenticated_endpoint": "unauthenticated_access",
    "sensitive_data_exposure": "data_exposure",
    "cors_credentialed_origin_reflection": "misconfig",
    "authenticated_content_cacheable": "data_exposure",
    "exposed_version_control": "source_disclosure",
    "exposed_env_file": "credential_exposure",
    "exposed_config_file": "info_disclosure",
    "exposed_backup_file": "source_disclosure",
    "exposed_debug_console": "rce",
    "exposed_debug_endpoint": "info_disclosure",
    "debug_error_page": "info_disclosure",
    "exposed_route_catalog": "info_disclosure",
}


def _vuln_query() -> str:
    return next(q for q in fact_queries.FINDING_QUERIES if q["name"] == "vulnerabilities")["query"]


def _projected_row(**values) -> dict:
    """A row with EXACTLY the projection's keys, as the scorer receives it."""
    aliases = re.findall(r"\bAS (\w+)", _vuln_query())
    row = {a: None for a in aliases}
    unknown = set(values) - set(row)
    assert not unknown, f"not in the projection: {unknown}"
    row.update(values)
    return row


def _candidate(**over):
    base = {"id": "re1", "label": "Vulnerability", "source": "route_exposure", "severity": "info",
            "host": "h1", "needs_agent_confirmation": True, "type": "unauthenticated_endpoint"}
    base.update(over)
    return base


class TestTiering(unittest.TestCase):
    def test_confidence_row(self):
        self.assertEqual(sm.CONFIDENCE_BY_SOURCE["route_exposure"], 0.75)

    def test_a_pending_info_lead_is_t4(self):
        result = sm.score(_candidate(), sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.tier, "T4")

    def test_a_proven_lead_is_t1(self):
        result = sm.score(_candidate(), sm.ProjectFacts(proven_finding_ids={"re1"}))
        self.assertEqual(result.tier, "T1")

    def test_custom_confirms_is_not_proof(self):
        proof = next(q for q in fact_queries.PROJECT_FACT_QUERIES if q["name"] == "proof")["query"]
        self.assertIn("vulnerability_confirmed", proof)
        self.assertNotIn("'custom'", proof)

    def test_a_signature_finding_gets_a_real_tier(self):
        finding = _candidate(id="re2", severity="high", needs_agent_confirmation=False,
                             type="exposed_env_file")
        result = sm.score(finding, sm.ProjectFacts(live_hosts={"h1"}))
        self.assertIn(result.tier, ("T1", "T2", "T3"))
        self.assertIn("credential_exposure", result.signals)
        self.assertNotEqual(result.tier, sm.score(_candidate(), sm.ProjectFacts(live_hosts={"h1"})).tier)


class TestClasses(unittest.TestCase):
    def test_one_class_per_type(self):
        self.assertEqual(set(sm.ROUTE_EXPOSURE_CLASSES), set(ROUTE_TYPES))
        for vtype, name in ROUTE_TYPES.items():
            with self.subTest(vtype=vtype):
                klass = sm._class_for(_candidate(type=vtype))
                self.assertEqual(klass.name, name)
                self.assertLessEqual(klass.impact, 0.75)

    def test_no_route_type_is_a_security_check_type(self):
        """T33: `_class_for` routes by type before source for every other writer."""
        self.assertFalse(set(sm.ROUTE_EXPOSURE_CLASSES) & set(sm.SECURITY_CHECK_CLASSES))

    def test_secret_in_response_is_classed_by_its_detector(self):
        klass = sm._class_for(_candidate(type="secret_exposure", secret_types=["AWS Access Key ID"]))
        self.assertEqual(klass, sm.classify_secret("AWS Access Key ID"))
        self.assertEqual(sm._class_for(_candidate(type="secret_exposure")), sm.classify_secret(None))

    def test_an_unknown_type_falls_back(self):
        self.assertIs(sm._class_for(_candidate(type="something_new")), sm.CLASS_DEFAULT)
        self.assertIs(sm._class_for(_candidate(type=None)), sm.CLASS_DEFAULT)

    def test_the_projection_carries_what_the_route_branch_reads(self):
        q = _vuln_query()
        for field in ("v.source AS source", "v.type AS type", "v.matched_at AS matched_at",
                      "v.secret_types AS secret_types"):
            self.assertIn(field, q)

    def test_a_projection_shaped_row_scores_with_its_class(self):
        row = _projected_row(id="re3", label="Vulnerability", source="route_exposure",
                             severity="high", type="exposed_version_control",
                             matched_at="http://h1/.git/HEAD")
        self.assertEqual(sm._class_for(row).name, "source_disclosure")
        result = sm.score(row, sm.ProjectFacts())
        self.assertIn("source_disclosure", result.signals)
        secret = _projected_row(source="route_exposure", type="secret_exposure",
                                secret_types=["GitHub Personal Access Token"])
        self.assertEqual(sm._class_for(secret), sm.classify_secret("GitHub Personal Access Token"))


class TestReview(unittest.TestCase):
    def test_the_builtin_review_never_judges_route_exposure(self):
        self.assertIn("route_exposure", evidence.SKIP_REVIEW_SOURCES)


class TestGrouping(unittest.TestCase):
    def _key(self, **finding):
        return grouping.group_key({"source": "route_exposure", "id": "x", **finding})

    def test_the_same_path_on_several_hosts_is_one_group(self):
        a = self._key(type="exposed_env_file", matched_at="http://a.example/.env")
        b = self._key(type="exposed_env_file", matched_at="https://b.example:8443/.env")
        self.assertEqual(a, b)
        self.assertEqual(a, "route:exposed_env_file:/.env")
        self.assertNotEqual(a, self._key(type="exposed_config_file", matched_at="http://a.example/.env"))

    def test_header_policies_group_per_host(self):
        for kind in ("cors_credentialed_origin_reflection", "authenticated_content_cacheable"):
            a = self._key(type=kind, matched_at="http://a.example/api/profile")
            b = self._key(type=kind, matched_at="http://a.example/api/other")
            c = self._key(type=kind, matched_at="http://b.example/api/profile")
            self.assertEqual(a, b)
            self.assertNotEqual(a, c)
            self.assertEqual(a, f"route:{kind}:a.example")

    def test_id_segments_collapse(self):
        keys = {self._key(type="unauthenticated_endpoint", matched_at=f"http://h/api/v1/orders/{seg}")
                for seg in ("42", "43", "0f8fad5b-d9cb-469f-a165-70867728950e", "a" * 24)}
        self.assertEqual(keys, {"route:unauthenticated_endpoint:/api/v1/orders/:id"})
        self.assertEqual(grouping._route_template("/api/v2/items"), "/api/v2/items")

    def test_never_raises_on_missing_fields(self):
        self.assertEqual(self._key(), "route::/")
        self.assertTrue(self._key(type="exposed_env_file", matched_at="http://[bad"))
        self.assertTrue(self._key(matched_at=None, type=None))


if __name__ == "__main__":
    unittest.main()
