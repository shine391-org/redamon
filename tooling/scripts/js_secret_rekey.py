#!/usr/bin/env python3
"""Re-key JS Recon secrets whose match the bounded patterns shorten. DRY RUN BY DEFAULT.

WHY

A JS Recon Secret's id is a hash of its pattern name, its matched text and its
file (recon/helpers/js_recon/patterns.py `_make_finding_id`). About 70
keyword-anchored patterns used a bare `.*` between the keyword and the value,
so on a minified line a match ran from the keyword to the LAST candidate value
on the line. They now allow at most 120 characters and take the NEAREST value
(plan 05.4), so such a match is shorter and its finding gets a new id. The next
JS Recon run prunes the old node; a muted or human-judged one is kept as
stale, and everything that names its old id would be left behind:

  - the `:Muted` label and the mute properties on the node;
  - the Priority Board layers (`triage_*`), a person's DECISION included;
  - the agent's proof edges `(:ChainFinding)-[:CONFIRMS]->(finding)`;
  - `NodeFilterExemption.nodeKey`, `Remediation.findingIds`,
    `CapturedHttpTransaction.findingId` in Postgres.

WHAT IT DOES

For every `Secret {source: 'js_recon'}` of a project it finds the pattern that
produced the node (the one whose id hash reproduces the node's), and runs that
pattern's CURRENT regex over the stored `matched_text`:
  - the same match       -> nothing to do;
  - a shorter match      -> the finding moves to the id the scanner now writes:
    renamed in place when nothing holds that id yet (the upgrade order: run this
    before the first scan on the new release), so every layer, the mute,
    `stale_since` and the CONFIRMS edges stay as they were; otherwise its layers
    and mute move onto the new node (as tooling/scripts/triage_graph_migrate.py
    merges duplicates), its CONFIRMS edges are re-created there, and the old
    node is deleted;
  - no match at all      -> left alone and listed: the pattern no longer reports
    it (the old Azure AD pattern's false positives), so the next run prunes it,
    or keeps it as stale when a person muted or judged it;
  - no pattern reproduces the id (a custom pattern, a node from an older id
    scheme) -> left alone.
It never computes a score and never writes `updated_at`; the next publish
recombines.

  # what it would do, per project, changing nothing (the default)
  python tooling/scripts/js_secret_rekey.py --all

  # after a Neo4j and Postgres backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/js_secret_rekey.py --all --apply
  docker compose start agent webapp recon-orchestrator

It needs the Neo4j driver and psycopg (DATABASE_URL); the agent image has both.
Inside a container `localhost` is not the stack, so point the services check at
it, or `--apply` cannot see them running:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL -e AGENT_URL=http://agent:8080 -e WEBAPP_API_URL=http://webapp:3000 \\
    -e RECON_ORCHESTRATOR_URL=http://recon-orchestrator:8010 \\
    --entrypoint python redamon-agent tooling/scripts/js_secret_rekey.py --all

Idempotent: a second run finds nothing to re-key. Run it again after a project
import or a scan-version restore brings the old ids back.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_patterns():
    """The detector's pattern module, loaded by path: it is stdlib-only, but
    importing it through `recon.helpers` pulls the recon image's dependencies
    (dnspython), which the agent image this runs in does not have."""
    path = REPO_ROOT / "recon" / "helpers" / "js_recon" / "patterns.py"
    spec = importlib.util.spec_from_file_location("js_recon_patterns", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


patterns = _load_patterns()

from tooling.scripts.netlas_finding_rekey import _carried  # noqa: E402
from tooling.scripts.triage_graph_migrate import services_are_up  # noqa: E402

PROJECTS = """
    SELECT id, user_id
      FROM projects
     {scope}
     ORDER BY created_at
"""

JS_SECRETS = """
MATCH (s:Secret {user_id: $uid, project_id: $pid})
WHERE s.source = 'js_recon' AND s.matched_text IS NOT NULL
RETURN s.id AS id, s.matched_text AS matched_text, s.source_url AS source_url
ORDER BY id
"""

READ_NODES = """
MATCH (s:Secret {user_id: $uid, project_id: $pid})
WHERE s.id IN $ids
RETURN s.id AS id, s:Muted AS muted, properties(s) AS props
"""

RENAME = """
MATCH (s:Secret {id: $old, user_id: $uid, project_id: $pid})
SET s.id = $new, s.matched_text = $matched, s.sample = $sample
"""

MERGE_ONTO_NEW = """
MATCH (keep:Secret {id: $new, user_id: $uid, project_id: $pid})
{remove}SET keep += $carried
FOREACH (_ IN CASE WHEN $mute THEN [1] ELSE [] END | SET keep:Muted)
RETURN count(keep) AS n
"""

COPY_PROOF = """
MATCH (old:Secret {id: $old, user_id: $uid, project_id: $pid})
MATCH (new:Secret {id: $new, user_id: $uid, project_id: $pid})
MATCH (cf:ChainFinding {user_id: $uid, project_id: $pid})-[r:CONFIRMS]->(old)
MERGE (cf)-[r2:CONFIRMS]->(new)
SET r2 += properties(r)
RETURN count(r2) AS n
"""

DELETE_OLD = """
MATCH (s:Secret {id: $old, user_id: $uid, project_id: $pid})
DETACH DELETE s
"""


def _node_id(uid: str, pid: str, finding_hash: str) -> str:
    """The Secret node id graph_db/mixins/recon/js_recon_mixin.py writes."""
    return f"secret-{uid}-{pid}-{finding_hash}"


def plan_secret(uid: str, pid: str, node_id: str, matched_text: str, source_url) -> dict:
    """What the current patterns make of one stored JS Recon secret.

    {"status": "same" | "moved" | "unmatched" | "unknown", ...}; "moved" carries
    the new node id and match.
    """
    prefix = _node_id(uid, pid, "")
    if not node_id.startswith(prefix):
        return {"status": "unknown"}
    old_hash = node_id[len(prefix):]
    url = source_url or ""
    for pattern in patterns.JS_SECRET_PATTERNS:
        if patterns._make_finding_id(pattern["name"], matched_text, url) != old_hash:
            continue
        match = pattern["regex"].search(matched_text)
        if match is None:
            return {"status": "unmatched", "pattern": pattern["name"]}
        new_text = match.group(0)
        if new_text == matched_text:
            return {"status": "same"}
        new_hash = patterns._make_finding_id(pattern["name"], new_text, url)
        return {"status": "moved", "pattern": pattern["name"], "old_id": node_id,
                "new_id": _node_id(uid, pid, new_hash), "matched_text": new_text,
                "sample": patterns.redact(new_text)}
    return {"status": "unknown"}


def plan_project(session, project: dict) -> dict:
    """The re-keys one project needs. Reads the graph; writes nothing."""
    uid, pid = project["user_id"], project["id"]
    rekeys, unmatched = [], []
    for row in session.run(JS_SECRETS, uid=uid, pid=pid):
        plan = plan_secret(uid, pid, str(row["id"]), str(row["matched_text"]), row["source_url"])
        if plan["status"] == "moved":
            rekeys.append(plan)
        elif plan["status"] == "unmatched":
            unmatched.append({"old_id": str(row["id"]), "pattern": plan["pattern"]})
    return {"rekeys": rekeys, "unmatched": unmatched}


def rekey_graph(session, uid: str, pid: str, rekey: dict) -> str:
    """Move one finding to its new id: 'renamed', 'merged' or 'gone'."""
    old_id, new_id = rekey["old_id"], rekey["new_id"]
    nodes = {r["id"]: r for r in session.run(READ_NODES, uid=uid, pid=pid, ids=[old_id, new_id])}
    old = nodes.get(old_id)
    if old is None:
        return "gone"
    new = nodes.get(new_id)
    if new is None:
        session.run(RENAME, uid=uid, pid=pid, old=old_id, new=new_id,
                    matched=rekey["matched_text"], sample=rekey["sample"])
        return "renamed"
    carried, cleared, mute = _carried(old, new)
    remove = f"REMOVE {', '.join('keep.' + p for p in cleared)}\n" if cleared else ""
    session.run(MERGE_ONTO_NEW.replace("{remove}", remove), uid=uid, pid=pid,
                new=new_id, carried=carried, mute=mute)
    session.run(COPY_PROOF, uid=uid, pid=pid, old=old_id, new=new_id)
    session.run(DELETE_OLD, uid=uid, pid=pid, old=old_id)
    return "merged"


def rekey_postgres(cursor, pid: str, rekey: dict) -> None:
    """Point every row that names the old id at the new one."""
    params = {"pid": pid, "old": rekey["old_id"], "new": rekey["new_id"], "label": "Secret",
              "row_id": f"c{uuid.uuid4().hex[:24]}"}
    # (project_id, label, node_key) is unique: an exemption the new id already
    # has makes the copy redundant.
    cursor.execute(
        """
        INSERT INTO node_filter_exemptions
               (id, project_id, label, node_key, created_by, real_actor_user_id)
        SELECT %(row_id)s, project_id, label, %(new)s, created_by, real_actor_user_id
          FROM node_filter_exemptions
         WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
        ON CONFLICT (project_id, label, node_key) DO NOTHING
        """, params)
    cursor.execute(
        """
        DELETE FROM node_filter_exemptions
         WHERE project_id = %(pid)s AND label = %(label)s AND node_key = %(old)s
        """, params)
    cursor.execute(
        """
        UPDATE remediations r
           SET finding_ids = CASE WHEN %(new)s = ANY(r.finding_ids)
                                  THEN array_remove(r.finding_ids, %(old)s)
                                  ELSE array_replace(r.finding_ids, %(old)s, %(new)s) END
         WHERE r.project_id = %(pid)s AND %(old)s = ANY(r.finding_ids)
        """, params)
    cursor.execute(
        """
        UPDATE captured_http_transactions
           SET finding_id = %(new)s
         WHERE project_id = %(pid)s AND finding_id = %(old)s
        """, params)


def run(conn, driver, project_id: str | None, apply: bool, out=print) -> dict:
    """Plan every project and, with `apply`, re-key it. Returns the plan per project."""
    if project_id is not None and not project_id.strip():
        raise ValueError("a blank project id; pass --all to mean every project")
    with conn.cursor() as cur:
        cur.execute(PROJECTS.format(scope="WHERE id = %(pid)s" if project_id else ""),
                    {"pid": project_id} if project_id else {})
        cols = [c[0] for c in cur.description]
        projects = [dict(zip(cols, row)) for row in cur.fetchall()]

    summary = {}
    suffix = "" if apply else " (dry run)"
    with driver.session() as session:
        for project in projects:
            pid, uid = project["id"], project["user_id"]
            plan = plan_project(session, project)
            for u in plan["unmatched"]:
                out(f"[js secret rekey] {pid}: {u['old_id']} ({u['pattern']}) no longer matches; "
                    f"left alone, the next JS Recon run prunes it unless it is muted or judged")
            for r in plan["rekeys"]:
                out(f"[js secret rekey] {pid}: {r['old_id']} -> {r['new_id']} ({r['pattern']}){suffix}")
            outcomes = []
            if apply and plan["rekeys"]:
                # Postgres first: a run that dies after it re-plans the same
                # re-keys (the graph still holds the old ids) and its updates
                # are no-ops the second time.
                with conn.cursor() as cur:
                    for r in plan["rekeys"]:
                        rekey_postgres(cur, pid, r)
                conn.commit()
                for r in plan["rekeys"]:
                    outcomes.append(rekey_graph(session, uid, pid, r))
            if plan["rekeys"] or plan["unmatched"]:
                summary[pid] = {**plan, "outcomes": outcomes}
                counted = ", ".join(f"{outcomes.count(o)} {o}" for o in ("renamed", "merged", "gone")
                                    if outcomes.count(o))
                out(f"[js secret rekey] {pid}: {len(plan['rekeys'])} to re-key, "
                    f"{len(plan['unmatched'])} no longer matched"
                    + (f"; done: {counted}" if counted else ""))
    total = sum(len(p["rekeys"]) for p in summary.values())
    out(f"[js secret rekey] {'re-keyed' if apply else 'would re-key'} {total} secret(s) "
        f"in {len(summary)} project(s)")
    return summary


def _connect():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("DATABASE_URL is not set: the fix items and exemptions live in Postgres.")
    try:
        import psycopg
    except ImportError:
        raise SystemExit("psycopg is required. Run this in the agent image (see the docstring).")
    return psycopg.connect(url)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="one project id")
    target.add_argument("--all", action="store_true", help="every project")
    ap.add_argument("--apply", action="store_true", help="write; without it this only lists")
    ap.add_argument("--force", action="store_true",
                    help="skip the services-are-down check. Do not.")
    args = ap.parse_args(argv)
    if args.project is not None and not args.project.strip():
        ap.error("--project is blank (an unset variable?); pass --all to mean every project")

    if args.apply:
        up = [] if args.force else services_are_up()
        if up:
            print("REFUSING: these services are still running: " + ", ".join(up), file=sys.stderr)
            print("A scan writing during the re-key would create the new ids under it.",
                  file=sys.stderr)
            return 2

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "")))
    try:
        with _connect() as conn:
            run(conn, driver, None if args.all else args.project, args.apply)
    finally:
        driver.close()
    if not args.apply:
        print("Nothing was changed. Re-run with --apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
