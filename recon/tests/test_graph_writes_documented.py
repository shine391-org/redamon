"""The catalog must describe every edge the CODE can write.

The live-graph oracle in test_schema_catalog.py can only see what this
deployment happened to scan. A relationship belonging to a feature nobody ran
here is invisible to it, which is a large blind spot: most deployments run a
fraction of the eleven scanners.

This checks the other direction, against the code, and is fully hermetic - no
database, so unlike the live oracle it actually runs in CI.

It found five undocumented relationship types on its first run (HAS_IP,
DISCOVERED_FROM and the three ChainFinding FINDING_AFFECTS_* edges), plus a real
bug that had nothing to do with documentation: see the phantom test below.

The webapp's Cypher (webapp/src, tests excluded) is scanned too: its routes are
the live implementation of several graph reads, and a TS port once kept a
phantom the Python twin had fixed (drift-map #6). Every member of an
alternation `[:A|B]` counts, not only the first.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_PY = PROJECT_ROOT / "graph_db" / "schema_catalog.py"

#: Files that CONTAIN the documentation, or that carry illustrative Cypher for a
#: different purpose. Scanning them would let the schema prove itself correct by
#: quoting itself.
SKIP_FILES = {
    "schema_catalog.py",   # the catalog itself
    "base.py",             # the prompt: examples, not writes
    "tool_registry.py",    # tool descriptions
    "rce_prompts.py",      # attack-prompt examples against a generic graph
}

SEARCH_ROOTS = ("graph_db", "recon", "scanners", "recon_orchestrator", "agentic")
WEBAPP_SRC = PROJECT_ROOT / "webapp" / "src"

#: Placeholders that are not relationship types: `-[:REL]` in a worked example,
#: `-[:STEP_*]` in a docstring describing a family of edges.
NOT_A_TYPE = {"REL", "STEP_", "RUNS"}

#: Read on purpose although nothing writes them. Each entry needs its reason.
INTENTIONAL_PHANTOMS = {
    # The pre-unification spelling of HAS_BASE_URL. Readers match both until
    # tooling/scripts/triage_graph_migrate.py has rewritten every database.
    "HAS_BASEURL": "legacy alias of HAS_BASE_URL (drift-map 4.7)",
}

#: `-[r:A|B|:C*1..3]`: the type list after the colon, every member of it.
REL_TYPES = re.compile(r"-\[\w*:(\w+(?:\s*\|\s*:?\w+)*)")


def _load(path: Path, name: str):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


catalog = _load(CATALOG_PY, "schema_catalog")


def _python_files() -> list[Path]:
    out = []
    for root in SEARCH_ROOTS:
        d = PROJECT_ROOT / root
        if not d.exists():
            continue
        out += [
            f
            for f in d.rglob("*.py")
            if "test" not in str(f.relative_to(PROJECT_ROOT)) and f.name not in SKIP_FILES
        ]
    return out


def _webapp_files() -> list[Path]:
    """webapp/src TS/TSX, without its tests and mocks (their Cypher is fixtures).

    Excluded by test naming rather than by "test" in the path, which would also
    drop a route under a directory such as `latest/`.
    """
    if not WEBAPP_SRC.exists():
        return []
    return [
        f
        for ext in ("*.ts", "*.tsx")
        for f in WEBAPP_SRC.rglob(ext)
        if not re.search(r"\.(test|spec)\.tsx?$", f.name)
        and not {"__tests__", "__mocks__", "node_modules"} & set(f.parts)
    ]


def _source_files() -> list[Path]:
    return _python_files() + _webapp_files()


def _scan() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """(written, read) -> {relationship type: [file:line]}.

    A line carrying MERGE or CREATE writes the edge; anything else reads it.
    The variable binding is optional, so `-[r:WAF_BYPASS_VIA]->` counts as a
    write: missing that cost me two false phantoms on the first pass.
    """
    written: dict[str, list[str]] = {}
    read: dict[str, list[str]] = {}
    for f in _source_files():
        rel = f.relative_to(PROJECT_ROOT)
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").split("\n"), 1):
            for group in REL_TYPES.findall(line):
                for t in re.split(r"\s*\|\s*:?", group):
                    if t in NOT_A_TYPE:
                        continue
                    bucket = written if re.search(r"\b(MERGE|CREATE)\b", line) else read
                    bucket.setdefault(t, []).append(f"{rel}:{i}")
    return written, read


def test_every_relationship_the_code_writes_is_documented():
    """An edge the schema never mentions is an edge the agent cannot traverse.

    Nothing fails today when a scanner adds one: the graph simply grows a
    connection the agent is blind to, and the answer comes back incomplete
    rather than wrong, which is much harder to notice.
    """
    written, _ = _scan()
    missing = {t: v for t, v in written.items() if t not in catalog.RELATIONSHIP_TYPES}
    assert not missing, (
        f"{len(missing)} relationship type(s) are written by the code but absent "
        "from the schema catalog, so the agent cannot traverse them:\n"
        + "\n".join(f"  {t}  ({v[0]})" for t, v in sorted(missing.items()))
    )


def test_no_query_reads_a_relationship_nothing_ever_writes():
    """A phantom edge: a query that can never match.

    This is not a documentation problem, it is a silent logic bug. It found
    `user_input_mixin.py` reading `(p)-[:HAS_SERVICE]->(:Service)` where every
    writer creates `RUNS_SERVICE`, so the Httpx partial-recon modal reported
    `existing_baseurls_count` as 0 no matter how many existed. No error, no
    empty-result warning - just a number that was always zero.
    """
    written, read = _scan()
    phantom = {
        t: v for t, v in read.items()
        if t not in written and t not in INTENTIONAL_PHANTOMS
    }
    assert not phantom, (
        "relationship type(s) are READ by a query but written NOWHERE, so those "
        "patterns can never match:\n"
        + "\n".join(f"  {t}  ({', '.join(v[:2])})" for t, v in sorted(phantom.items()))
    )


def test_every_intentional_phantom_is_still_read_and_still_unwritten():
    """An allowlist entry that no longer applies hides the next real phantom
    of the same name."""
    written, read = _scan()
    stale = sorted(t for t in INTENTIONAL_PHANTOMS if t in written or t not in read)
    assert not stale, f"INTENTIONAL_PHANTOMS entries no longer needed: {stale}"


def test_every_member_of_an_alternation_is_read():
    """`[:A|B]` used to yield A only, which is how a phantom second member
    stayed invisible."""
    line = "MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(b) OPTIONAL MATCH (a)<-[r:X | :Y*1..2]-(c)"
    found = [t for g in REL_TYPES.findall(line) for t in re.split(r"\s*\|\s*:?", g)]
    assert found == ["HAS_BASE_URL", "HAS_BASEURL", "X", "Y"]


def test_the_graph_view_clusters_only_edges_something_writes():
    """STRUCTURAL_EDGE_TYPES is a string list, not Cypher, so the scan above
    cannot see it; an entry nothing writes (POWERED_BY was one) is dead."""
    cluster = WEBAPP_SRC / "app" / "graph" / "utils" / "clusterNodes.ts"
    if not cluster.exists():
        pytest.skip("webapp/ is not in this checkout")
    block = re.search(r"STRUCTURAL_EDGE_TYPES = new Set\(\[(.*?)\]\)",
                      cluster.read_text(encoding="utf-8"), re.S)
    assert block, "STRUCTURAL_EDGE_TYPES not found in clusterNodes.ts"
    types = re.findall(r"'([A-Z_]+)'", block.group(1))
    assert len(types) > 10
    written, _ = _scan()
    dead = sorted(t for t in types if t not in written and t not in INTENTIONAL_PHANTOMS)
    assert not dead, f"STRUCTURAL_EDGE_TYPES names edges nothing writes: {dead}"


def test_the_scan_reads_the_webapp_cypher():
    """The webapp routes carry graph reads of their own; a scan that silently
    found none of them would pass the phantom test vacuously."""
    if not (PROJECT_ROOT / "webapp").exists():
        pytest.skip("webapp/ is not in this checkout")
    files = _webapp_files()
    assert any(f.name == "route.ts" and "graph-inputs" in str(f) for f in files)
    _, read = _scan()
    webapp_reads = {t for t, v in read.items() if any(x.startswith("webapp") for x in v)}
    assert len(webapp_reads) > 20, (
        f"only {len(webapp_reads)} relationship types read in webapp/src; the "
        "webapp file filter is probably wrong"
    )


def _properties_written() -> dict[str, set[str]]:
    """{label: property names} from explicit Cypher across the codebase.

    Only sees properties written literally - `SET n.foo = ...` or a `{foo: $x}`
    map. The 22 labels using `SET n += $props` build their dict in Python, so
    their names appear in no file and only the live graph knows them. That is
    why BOTH oracles exist: this one covers features nobody ran here, the live
    one covers the dynamic writers.
    """
    out: dict[str, set[str]] = {}
    for f in _python_files():
        src = f.read_text(encoding="utf-8", errors="replace")
        blocks = re.findall(r'"""(.*?)"""', src, re.S) + re.findall(r'"([^"\n]{30,})"', src)
        for q in blocks:
            if not re.search(r"\b(MERGE|CREATE|SET)\b", q):
                continue
            binds: dict[str, str] = {}
            for var, lab in re.findall(r"\((\w+):(\w+)", q):
                binds.setdefault(var, lab)
            for _var, lab, body in re.findall(r"\((\w+):(\w+)\s*\{([^}]*)\}", q):
                for prop in re.findall(r"(\w+)\s*:", body):
                    out.setdefault(lab, set()).add(prop)
            for var, prop in re.findall(r"\b(\w+)\.(\w+)\s*=", q):
                if var in binds:
                    out.setdefault(binds[var], set()).add(prop)
    return out


def test_every_property_the_code_writes_is_documented():
    """Same blind spot as relationships had.

    The live-graph oracle only sees properties this deployment happened to
    produce. EPSS scoring on CVE, cpe_vendor on Technology, fixed_version on
    Vulnerability - 30 of these existed with no schema entry because no scan
    here had ever written one.
    """
    render = _load(PROJECT_ROOT / "graph_db" / "schema_render.py", "schema_render")
    doc = render.render_schema() + (
        PROJECT_ROOT / "agentic" / "prompts" / "base.py"
    ).read_text(encoding="utf-8")
    ignore = {"user_id", "project_id"}
    missing = {}
    for lab, props in _properties_written().items():
        if lab not in catalog.DOCUMENTED:
            continue  # label coverage is the other suite's job
        # A leading underscore is the write-lock idiom (`SET n._prune_lock =
        # true REMOVE n._prune_lock`): set and removed in the same statement,
        # so it is never stored and documenting it would teach a phantom.
        gone = sorted(
            p for p in props
            if p not in ignore and not p.startswith(("triage", "_")) and p not in doc
        )
        if gone:
            missing[lab] = gone
    assert not missing, (
        f"{sum(len(v) for v in missing.values())} propert(ies) are written by the "
        "code but absent from the schema, so the agent cannot name them:\n"
        + "\n".join(f"  {lab}: {', '.join(ps)}" for lab, ps in sorted(missing.items()))
    )


def test_the_scan_finds_a_plausible_number_of_writes():
    """Guards against the scan silently matching nothing and passing vacuously."""
    written, _ = _scan()
    assert len(written) > 50, (
        f"only {len(written)} relationship types found in the codebase; the "
        "scanner or the SKIP list is probably wrong, making both tests above vacuous"
    )


if __name__ == "__main__":
    passed, failures = 0, []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append(name)
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append(name)
    print()
    print(f"{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)


# ---------------------------------------------------------------------------
# Properties applied via `SET n += $props`
# ---------------------------------------------------------------------------
# The scan above reads property names out of the Cypher text, so it cannot see a
# property whose name only ever exists as a dict key in Python. The Domain's
# props are one such dict. A Domain node is the org, shared by every scan root
# under it, so it carries no per-run scope fields any more (wildcard_mode,
# filtered_mode, ...): what was scanned lives in the project's scope groups.
# That retirement gets a behavioural test, since the scan cannot see it.

class _FakeSession:
    """Captures every Cypher call instead of running it."""

    def __init__(self, sink):
        self.sink = sink

    def run(self, query, **params):
        self.sink.append((query, params))
        return []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDriver:
    def __init__(self, sink):
        self.sink = sink

    def session(self):
        return _FakeSession(self.sink)


def _domain_props_for(metadata_extra: dict) -> dict:
    """Run the real mixin against a fake driver and return the Domain props."""
    from graph_db.mixins.recon.domain_mixin import DomainMixin

    class _Client(DomainMixin):
        def __init__(self, sink):
            self.driver = _FakeDriver(sink)

    sink: list = []
    recon_data = {
        "metadata": {"root_domain": "example.com", "target": "example.com",
                     **metadata_extra},
        "whois": {}, "subdomains": [], "dns": {},
    }
    _Client(sink).update_graph_from_domain_discovery(recon_data, "u1", "p1")
    for query, params in sink:
        if "MERGE (d:Domain" in query:
            return params["props"]
    raise AssertionError("the Domain MERGE never ran")


RETIRED = ("target", "filtered_mode", "wildcard_mode", "subdomain_filter",
           "modules_executed", "anonymous_mode", "bruteforce_mode", "scan_type")


def test_the_run_scope_fields_never_reach_the_org_domain():
    props = _domain_props_for({k: True for k in RETIRED} | {"scan_timestamp": "t"})
    assert not set(RETIRED) & set(props)
    assert props["scan_timestamp"] == "t"


def test_an_older_recon_file_writes_none_either():
    assert not set(RETIRED) & set(_domain_props_for({}))


def test_the_schema_declares_the_org_model():
    # Declared in ONE place; schema_catalog.py is generated from it.
    sections = (PROJECT_ROOT / "graph_db" / "schema_sections.md").read_text()
    domain_block = sections.split("**Domain**", 1)[1].split("**Subdomain**", 1)[0]
    subdomain_block = sections.split("**Subdomain**", 1)[1].split("**", 1)[0]
    assert "wildcard_mode" not in domain_block
    assert "recon_coverage_roots" in domain_block
    assert "is_scan_root" in subdomain_block
