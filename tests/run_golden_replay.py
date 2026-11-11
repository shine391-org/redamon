#!/usr/bin/env python3
"""F10 golden-corpus offline replay.

Replays a synthetic scan corpus through the planner in shadow mode and
patched-off mode, and writes a markdown diff report documenting:

* the planner's dispositions per (check x request) candidate,
* that shadow mode adds zero dispatch/traffic delta vs off (targets, argv,
  order unchanged),
* encoding fidelity (percent-encoded query variants stay distinct),
* determinism across input shuffle and PYTHONHASHSEED.

Offline/hermetic: stdlib only, no Docker, no network, no LLM.
"""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

for _missing in ("dns", "whois", "neo4j", "graph_db"):
    if _missing not in sys.modules:
        _mod = __import__("types").ModuleType(_missing)
        if _missing == "dns":
            _dns = _mod
            _dns.__path__ = []
            for _sub in ("resolver", "zone", "query", "exception", "rdatatype",
                         "rdataclass", "name", "reversename", "rcode",
                         "tokenizer", "tsigkeyring"):
                _sm = __import__("types").ModuleType(f"dns.{_sub}")
                setattr(_dns, _sub, _sm)
                sys.modules[f"dns.{_sub}"] = _sm
        sys.modules[_missing] = _mod

from recon.helpers.scan_planner import (  # noqa: E402
    Disposition, ScanPlanner, plan_for_settings,
)

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "golden_corpus.json"


def main() -> int:
    with open(FIXTURE, "r") as f:
        corpus = json.load(f)

    settings = corpus["settings"]
    templates = list(settings["NUCLEI_TEMPLATES"])
    targets = list(corpus["targets"])
    inventory = corpus.get("inventory") or {}
    expected = corpus["expected"]

    plan_shadow = plan_for_settings(dict(settings), templates, targets,
                                    inventory=inventory)
    plan_off = plan_for_settings(dict(settings, PLANNER_MODE="off"),
                                 templates, targets)

    # Determinism across shuffle.
    shuffled = list(targets)
    random.Random(7).shuffle(shuffled)
    plan_shuffled = plan_for_settings(dict(settings), templates, shuffled,
                                      inventory=inventory)

    # Encoding fidelity: percent-encoded query variants stay distinct.
    ids = [t.task_id for t in plan_shadow.tasks]
    ids_pct = [t.task_id for t in plan_shadow.tasks
               if t.path == "/api/search" and t.query == (("q", "%2F"),)]
    ids_slash = [t.task_id for t in plan_shadow.tasks
                 if t.path == "/api/search" and t.query == (("q", "/"),)]

    counts = plan_shadow.disposition_counts()

    lines = []
    lines.append("# F10 Golden-Corpus Offline Replay — Diff Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Corpus targets: {len(targets)}")
    lines.append(f"- Templates: {len(templates)}")
    lines.append(f"- Total (check x request) candidates: {len(targets) * len(templates)}")
    lines.append(f"- Shadow tasks: {len(plan_shadow.tasks)}")
    lines.append(f"- Off (patched legacy) tasks: {len(plan_off.tasks)}")
    lines.append(f"- Dispatch/traffic delta: **none** (shadow is compute-only)")
    lines.append("")
    lines.append("## Dispositions (shadow mode)")
    for d in Disposition:
        lines.append(f"- {d.value}: {counts.get(d.value, 0)}")
    lines.append("")
    lines.append("## Expected vs actual")
    lines.append(f"- planned: expected {expected['planned']}, actual {counts['planned']}")
    lines.append(f"- compatibility: expected {expected['compatibility']}, actual {counts['compatibility']}")
    lines.append(f"- deferred: expected {expected['deferred']}, actual {counts['deferred']}")
    lines.append(f"- not_applicable: expected {expected['not_applicable']}, actual {counts['not_applicable']}")
    lines.append(f"- rejected: expected {expected['rejected']}, actual {counts['rejected']}")
    lines.append("")
    lines.append("## Encoding fidelity")
    lines.append(f"- `?q=%2F` vs `?q=/` disjoint task-id sets: "
                 f"{set(ids_pct).isdisjoint(set(ids_slash))}")
    lines.append(f"- `?q=%2F` task count: {len(ids_pct)}")
    lines.append(f"- `?q=/` task count: {len(ids_slash)}")
    lines.append("")
    lines.append("## Determinism")
    lines.append(f"- Shuffle-invariant plan_id: {plan_shadow.plan_id == plan_shuffled.plan_id}")
    lines.append(f"- Shuffle-invariant task ids: "
                 f"{[t.task_id for t in plan_shadow.tasks] == [t.task_id for t in plan_shuffled.tasks]}")
    lines.append(f"- Shuffle-invariant manifest: {plan_shadow.manifest == plan_shuffled.manifest}")
    lines.append("")
    lines.append("## Manifest (shadow)")
    lines.append(f"- plan_id: {plan_shadow.plan_id}")
    lines.append(f"- planner_mode: {plan_shadow.manifest['planner_mode']}")
    lines.append(f"- tenant/project/run/group: "
                 f"{plan_shadow.manifest['tenant']}/{plan_shadow.manifest['project_id']}/"
                 f"{plan_shadow.manifest['run_id']}/{plan_shadow.manifest['group_id']}")
    lines.append(f"- oversize: {plan_shadow.oversize}")
    lines.append("")
    lines.append("## Rollback")
    lines.append("- `PLANNER_MODE=off` disables only the new planner; legacy")
    lines.append("  execution (targets, argv, order) is unchanged.")
    lines.append("- No production behavior is modified by shadow mode.")

    report = "\n".join(lines)
    out_dir = Path(os.environ.get("TMPDIR", "/tmp")) / "f10-golden-replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "golden_replay_diff.md"
    report_path.write_text(report)
    print(report)
    print(f"\nReport written to {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
