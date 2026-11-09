#!/usr/bin/env python3
"""Run one test file per disposable offline container; no daemon socket in tests.

Usage: python3 docs/recon-quality/p0/run.py --output /absolute/scratch/p0
Run from any checkout; requires the pinned image already in the local Docker store.
No pulls, package installs, production services, or target traffic.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

IMAGE = "sha256:6990dc80a76d739d02c0a1a79c3cde50bee27ce39f129d48d1f3e58e1ebd5ae1"
FILES = [
    "recon/tests/test_nuclei_policy_parity.py",
    "recon/tests/test_auth_no_cross_host_leak.py",
    "recon/tests/test_engagement_identity_header.py",
    "recon/tests/test_nuclei_runtime_cap.py",
    "recon/tests/test_target_helpers_union.py",
    "recon/tests/test_no_b_large_inputs.py",
    "recon/tests/test_declared_only_consumers.py",
    "recon/tests/test_nuclei_two_pass.py",
    "recon/tests/test_nuclei_coverage.py",
    "recon/tests/test_nuclei_ai_planner.py",
    "recon/tests/test_nuclei_ai_vuln_scan_wiring.py",
    "recon/tests/test_fix_nuclei_coverage.py",
    "recon/tests/test_regression_nuclei_crash_partial_output.py",
    "recon/tests/test_regression_nuclei_early_return_checks.py",
    "recon/tests/test_fix_partial_nuclei_technologies.py",
    "recon/tests/test_coverage_prune.py",
    "tests/test_recon_coverage_graph.py",
    "tests/test_js_recon_graph_ingestion.py",
    "recon/tests/test_js_recon_validation_states.py",
    "recon/tests/test_js_recon_host_health.py",
    "recon/tests/test_jev_resource_enum_flow.py",
    "recon/tests/test_ffuf.py",
    "recon/tests/test_arjun.py",
    "recon/tests/test_recon_quality_baseline.py",
    "recon/tests/test_js_recon.py",
    "recon/tests/test_js_recon_timeout.py",
    "recon/tests/test_js_recon_download_guard.py",
    "recon/tests/test_js_recon_ssrf.py",
    "recon/tests/test_catchall_probe.py",
    "recon/tests/test_jev_ffuf_base_paths.py",
    "recon/tests/test_nuclei_cve_findings_reach_graph.py",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("files", nargs="*", default=FILES)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    if not args.image.startswith("sha256:") or len(args.image) != 71:
        parser.error("--image must be an immutable full local image ID")
    int(args.image[7:], 16)
    if output.is_relative_to(root):
        parser.error("--output must be outside the read-only source checkout")
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["docker", "image", "inspect", args.image], check=True, stdout=subprocess.DEVNULL)
    results = []
    for filename in args.files:
        source = (root / filename).resolve()
        if not source.is_relative_to(root) or not source.is_file() or source.suffix != ".py":
            parser.error(f"invalid test file {filename!r}")
        run = output / filename.replace("/", "__").removesuffix(".py")
        run.mkdir()
        # The test image's configured uid may differ from the host's uid.
        os.chmod(run, 0o777)
        scratch = run / "scratch"
        scratch.mkdir(mode=0o777)
        os.chmod(scratch, 0o777)
        name = "rq-p0-" + uuid.uuid4().hex[:12]
        cmd = ["docker", "run", "--rm", "--name", name, "--pull", "never",
               "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
               "--entrypoint", "python3", "-e", "PYTHONPATH=/work:/work/recon",
               "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONHASHSEED=0", "-e", "TMPDIR=/scratch",
               "-v", f"{scratch}:/scratch:rw",
               "-v", f"{root}:/work:ro", "-v", f"{run}:/evidence:rw", "-w", "/work",
               args.image, "-m", "pytest", "-q", "-rxXs", "-p", "no:cacheprovider",
               "--junitxml=/evidence/junit.xml", filename]
        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            text, rc = proc.stdout, proc.returncode
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            text = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            text += "\nHARNESS TIMEOUT: disposable container removed\n"
            rc = 124
        (run / "pytest.log").write_text(text)
        record = {"file": filename, "rc": rc, "seconds": round(time.monotonic() - start, 3), "command": cmd}
        if (run / "junit.xml").exists():
            cases = list(ET.parse(run / "junit.xml").iter("testcase"))
            def skipped_type(case):
                node = case.find("skipped")
                return node.get("type", "") if node is not None else None
            record.update(tests=len(cases), failed=sum(c.find("failure") is not None for c in cases),
                          errors=sum(c.find("error") is not None for c in cases),
                          skipped=sum(skipped_type(c) is not None and skipped_type(c) != "pytest.xfail" for c in cases),
                          xfail=sum(skipped_type(c) == "pytest.xfail" for c in cases))
            record["passed"] = record["tests"] - sum(record[k] for k in ("failed", "errors", "skipped", "xfail"))
        results.append(record)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps({k: v for k, v in record.items() if k != "command"}), flush=True)
    totals = {k: sum(r.get(k, 0) for r in results) for k in ("tests", "passed", "failed", "errors", "skipped", "xfail")}
    (output / "totals.json").write_text(json.dumps(totals, indent=2) + "\n")
    print(json.dumps(totals))
    return int(any(r["rc"] != 0 or "tests" not in r for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
