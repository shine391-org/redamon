"""Discovery-consumer accounting: admitted counts and recorded statuses.

The Nuclei detection consumer is accounted with what it was GIVEN
(``total_urls_selected``), falling back to the legacy ``total_urls_scanned``
field for artifacts that predate it. The coverage/selection reader accepts
every recorded plan status, including ``not_scanned``.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import chunk_evidence as ce  # noqa: E402
from recon.helpers import discovery_adapters as da  # noqa: E402


def _recon(metadata):
    return {
        "resource_enum": {"by_base_url": {}, "summary": {}},
        "vuln_scan": {"scan_metadata": metadata},
    }


class TestNucleiDetectionAdmittedCount:
    def test_selected_is_the_admitted_count(self):
        inv = da.finalize_inventory(_recon({"total_urls_selected": 7,
                                            "total_urls_scanned": 2}))
        assert inv["consumers"]["nuclei_detection"]["admitted"] == 7

    def test_legacy_scanned_is_the_fallback(self):
        inv = da.finalize_inventory(_recon({"total_urls_scanned": 2}))
        assert inv["consumers"]["nuclei_detection"]["admitted"] == 2

    def test_no_counts_at_all_is_zero_not_an_error(self):
        inv = da.finalize_inventory(_recon({}))
        assert inv["consumers"]["nuclei_detection"]["admitted"] == 0

    def test_a_non_numeric_selected_falls_back_to_scanned(self):
        inv = da.finalize_inventory(_recon({"total_urls_selected": "many",
                                            "total_urls_scanned": 3}))
        assert inv["consumers"]["nuclei_detection"]["admitted"] == 3


class TestRecordedStatuses:
    def test_summarize_selection_accepts_not_scanned(self):
        out = ce.summarize_selection(
            {"selection_coverage": {"module": "vuln_scan", "status": "not_scanned",
                                    "exhaustive": False,
                                    "targets": {"count": 4},
                                    "outcomes": {"completed": 0, "unknown": 1}}})
        assert out == {"modules": {"vuln_scan": {
            "status": "not_scanned", "exhaustive": False, "targets": {"count": 4},
            "outcomes": {"completed": 0, "unknown": 1},
            "reasons": ["selection_recorded"]}}}

    def test_summarize_coverage_counts_a_not_scanned_row(self):
        out = ce.summarize_coverage({"js_recon": {"coverage": {"hosts": {
            "https://a.example:443": {"status": "not_scanned"},
            "https://b.example:443": {"status": "complete"},
        }}}})
        assert out == {"js_recon": {"complete": 1, "partial": 0, "no_input": 0,
                                     "failed": 0, "not_scanned": 1, "recorded": True,
                                     "unknown": 0}}
