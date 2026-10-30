"""Text the route-exposure parts of access_control, path_traversal and rce share.

Never a part itself: each part constant concatenates what it needs at import
time, so every part stays one static string the parts registry can hash. A part
whose site calls .format() (a TEMPLATE) must take these through `escape`, since
the Cypher and Python below carry literal braces.
"""

from __future__ import annotations


def escape(text: str) -> str:
    """Literal braces for a TEMPLATE part, which the builder .format()s."""
    return text.replace("{", "{{").replace("}", "}}")


def candidate_query(kinds, pending: bool = True) -> str:
    """The ordered, bounded pull of recon's route-exposure nodes of `kinds`."""
    kind_list = ", ".join(f"'{k}'" for k in kinds)
    flag = "true" if pending else "false"
    return (
        "```cypher\n"
        "MATCH (v:Vulnerability {source:'route_exposure'})\n"
        f"WHERE v.needs_agent_confirmation = {flag}\n"
        f"  AND v.exposure_kind IN [{kind_list}]\n"
        "  AND NOT (:ChainFinding)-[:CONFIRMS]->(v)\n"
        "OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)\n"
        "RETURN v.id AS id, v.exposure_kind AS kind, v.route_class AS route_class,\n"
        "       v.matched_at AS url, coalesce(e.method, v.http_method) AS method,\n"
        "       v.anon_status AS anon, v.authed_status AS authed, v.auth_expected_by AS expected,\n"
        "       any(x IN coalesce(v.auth_expected_by, []) WHERE x IN\n"
        "           ['openapi', 'siblings_locked', 'version_locked', 'vary_auth']) AS login_declared,\n"
        "       v.leak_signals AS leaks, v.pii_types AS pii, v.sensitive_fields AS fields,\n"
        "       v.generated_by AS generated_by, v.variant_of AS variant_of, v.signature AS signature,\n"
        "       v.confidence AS confidence, v.route_jev_sensitivity AS jev,\n"
        "       v.route_jev_kind AS jev_kind, v.anon_page_class AS page_class\n"
        "ORDER BY CASE WHEN (v.anon_page_class IN ['login_only', 'parked', 'default', 'placeholder', 'error']\n"
        "                    AND coalesce(v.anon_page_class_confidence, 0) >= 70)\n"
        "               OR (v.route_jev_kind = 'public_content'\n"
        "                   AND coalesce(v.route_jev_kind_confidence, 0) >= 70) THEN 1 ELSE 0 END,\n"
        "         coalesce(v.route_jev_sensitivity, -1) DESC, v.confidence DESC, v.id\n"
        "LIMIT 50\n"
        "```\n"
        "`jev` (sensitivity 0-100), `jev_kind` and `page_class` are TypeSafe Jev's reading of "
        "the lead, null when the scan did not ask Jev. They set the order only: the leads Jev "
        "reads as most sensitive come first, the ones it reads as a login wall, an error page or "
        "public content come last. They never prove or reject a lead on their own.\n"
        "Page with `AND v.id > '<last id>'` added to the WHERE. Copy every `id` exactly: the "
        "record step needs it. To read a node's fields again, re-run THIS query with "
        "`AND v.id IN ['<id>', ...]`; never ask for them in plain English: `expected` is the "
        "alias of `v.auth_expected_by`, and a plain-English question names properties that do "
        "not exist and gets None back for them."
    )


VALUES_IN_FILES = """
### Values stay in files (never in this conversation)

A tool result reaches the model, and a large one is only cut to a head and a tail,
so a body must never be a tool's output. Every recipe here:

1. writes the body to a kali-local file with execute_curl:
   `-s -o /tmp/rex-<id>-anon.body -w '%{http_code} %{size_download} %{content_type}' '<url>'`
   (flat names: curl -o creates no directory). execute_curl and execute_code run in
   the same kali sandbox, so execute_code reads that file; the fs_* tools work in the
   agent's /workspace and never see it, which is the point.
2. reads it with ONE execute_code script that prints only derived facts: status
   codes, sizes, key names, counts, kinds, valid/invalid, and 8-character SHA-256
   prefixes. Never a value, record, secret, token or cookie.
3. deletes it in that same script (os.remove) and prints nothing else from it.

Before `switch_skill`, `transition_phase` or `complete`, the execute_code you run
also removes every `/tmp/rex-*` file still there (glob, os.remove) and prints only
how many it removed: a body left behind is a value left on disk.

With `use_session=true` the flags `-v`, `-i`, `--trace`, `-D -` and `-o -` are
FORBIDDEN: they would echo the session's headers, a Set-Cookie or the body.
"""

RECORD_CONTRACT = """
### Recording a proof (same response, then verify)

- Fill `output_analysis.chain_findings` IN THE SAME RESPONSE that reads the proof
  (it is a field, not a tool): `finding_type: "vulnerability_confirmed"`,
  `related_finding_ids: ["<the exact id>"]`, `confidence` 80 or more, a `title` naming
  the route and what it proves, and `evidence` (statuses, sizes, hash prefixes, key
  names). Only a proof type at 70 or more promotes the node to T1.
- "Record X as confirmed" written in `actionable_findings`, `thought` or `reasoning`
  records NOTHING: it is kept as a note without an id. Only a `chain_findings` entry
  writes the CONFIRMS edge.
- ONE id per entry.
- A lead (`needs_agent_confirmation = true`) is confirmed ONLY in the access_control
  skill, against its proof standard: from any other skill its id writes nothing.
  Leave such a lead alone and name it in your final answer.
- NEVER put ids on `exploit_success`, `access_gained` or `credential_found`: those
  entries are dropped from the CONFIRMS path when an exploit succeeded, so the id
  would be lost silently. Record the confirmation first, then the impact (a
  console's output, a credential) as its own entry with NO ids.
- Before `action="complete"`, verify each one:
  `MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {id:'<ID>'}) RETURN cf.finding_type`.
  Missing means the entry was never in `chain_findings` or its id was wrong (both
  write nothing, silently): put the entry in your NEXT response's `chain_findings`
  with the exact id, before any `switch_skill` or `transition_phase`.
- A lead you REJECT (public by design, nothing sensitive) gets NO entry at all:
  list it in your final answer as rejected, with the reason.
"""

SAFETY_RULES = """
### Safety (these hold whatever the target answers)

- Methods: only GET, HEAD and OPTIONS against a lead's or a finding's URL (plus the
  single `1+1` console request where the rce part allows it). No form submit, no
  write, no DELETE, even on an open admin route.
- Actuator: never POST to any `/actuator/*` path; never run the nuclei templates
  `springboot-env-rce-chains` or `springboot-jolokia-rce` (they restart the
  application). `springboot-heapdump-bypass` is detection-only and allowed.
- Consoles: never guess or compute a PIN; never run an Ignition exploit chain.
- Origins: attacker origins use `.invalid`; a PoC file is written, never served; no
  live exfiltration endpoint.
- Values stay in files (above). Evidence holds key names, counts, statuses, header
  names and hash prefixes only.
- The tool confirmation, the RoE categories, the severity-phase cap and the phase
  gates still apply. Nothing here is a way around them.
"""
