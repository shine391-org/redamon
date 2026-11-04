"""The route-exposure parts of access_control, path_traversal and rce (plan §23.12).

With recon's route exposure module off, the three skills render byte-identical
text (the golden's ALL_OFF hashes). With it on, the new parts follow the
existing ones; each gated part is absent unless its switch AND the RoE allow it,
and its parent prints ENABLED / DISABLED to match. Every part names real tools
only and carries the record contract, the verify step, the rejection rule, the
forbidden actions and the values-in-files rule.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from record_skill_golden import ALL_OFF, ALL_TOOLS, render_workflow  # noqa: E402

GOLDEN = json.loads((Path(__file__).resolve().parent / "fixtures" / "skill_workflow_golden.json").read_text())
SKILLS = ("access_control", "path_traversal", "rce")
ON = {"ROUTE_EXPOSURE_ENABLED": True}
GATES = {"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True, "PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True,
         "RCE_HEAPDUMP_ANALYSIS_ENABLED": True}
ROE_OK = {"ROE_ALLOW_DATA_EXFILTRATION": True, "ROE_SENSITIVE_DATA_HANDLING": "limited_collection"}
REAL_TOOLS = {"execute_curl", "execute_code", "execute_playwright", "fs_write", "fs_list", "fs_delete",
              "job_spawn", "kali_shell", "query_graph", "graph_summary", "proxy_brain", "switch_skill"}


def _render(skill, settings, tools=ALL_TOOLS):
    return render_workflow(skill, settings, tools, False, [])


def _sha(parts):
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _text(skill, settings):
    return "\n".join(_render(skill, settings))


@pytest.mark.parametrize("skill", SKILLS)
def test_module_off_is_byte_identical(skill):
    for name, settings in (("defaults", {}), ("all_off", ALL_OFF)):
        assert _sha(_render(skill, settings)) == GOLDEN["workflow"][f"{name}/{skill}"]["sha256"]
    # The switches alone change nothing while the module is off.
    assert _sha(_render(skill, {**GATES, **ROE_OK})) == GOLDEN["workflow"][f"defaults/{skill}"]["sha256"]


@pytest.mark.parametrize("skill,new", [
    ("access_control", ["ROUTE EXPOSURE LEADS", "ROUTE EXPOSURE BROWSER LEADS"]),
    ("path_traversal", ["EXPOSED FILES RECON FOUND"]),
    ("rce", ["DEBUG CONSOLES AND ENDPOINTS RECON FOUND"]),
])
def test_module_on_appends_the_new_part_after_the_existing_ones(skill, new):
    off = _render(skill, {})
    on = _render(skill, ON)
    assert on[:len(off)] == off
    assert len(on) == len(off) + len(new)
    for part, marker in zip(on[len(off):], new):
        assert marker in part


@pytest.mark.parametrize("settings,git,val", [
    ({}, False, False),
    ({"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True}, False, False),          # switch, RoE forbids
    ({"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True, **ROE_OK}, True, False),
    ({"PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True}, False, True),         # switch only
    ({**GATES, **ROE_OK}, True, True),
])
def test_path_traversal_gates(settings, git, val):
    text = _text("path_traversal", {**ON, **settings})
    assert ("RECONSTRUCT AN EXPOSED .git" in text) is git
    assert ("VALIDATE A SECRET FROM AN EXPOSED FILE" in text) is val
    assert f"git reconstruction: {'ENABLED' if git else 'DISABLED'}" in text
    assert f"secret validation: {'ENABLED' if val else 'DISABLED'}" in text


def test_gated_parts_need_execute_code():
    tools = tuple(t for t in ALL_TOOLS if t != "execute_code")
    text = _text("path_traversal", {**ON, **GATES, **ROE_OK})
    assert "RECONSTRUCT AN EXPOSED .git" in text
    text = "\n".join(_render("path_traversal", {**ON, **GATES, **ROE_OK}, tools))
    assert "RECONSTRUCT AN EXPOSED .git" not in text and "git reconstruction: DISABLED" in text


@pytest.mark.parametrize("settings,on", [
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True}, False),
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True, "ROE_ALLOW_DATA_EXFILTRATION": True}, False),  # handling no_access
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True, **ROE_OK}, True),
    (ROE_OK, False),
])
def test_rce_heapdump_gate(settings, on):
    text = _text("rce", {**ON, **settings})
    assert ("ANALYSE AN EXPOSED HEAP DUMP" in text) is on
    assert f"heapdump analysis: {'ENABLED' if on else 'DISABLED'}" in text


# The existing parts' factory hashes are pinned in test_skill_override_compat.py.


def _new_parts():
    from prompts import (ACCESS_CONTROL_ROUTE_EXPOSURE_BROWSER_LEADS,
                         ACCESS_CONTROL_ROUTE_EXPOSURE_LEADS, PATH_TRAVERSAL_EXPOSED_FILES,
                         PATH_TRAVERSAL_GIT_RECONSTRUCT, PATH_TRAVERSAL_VALIDATE_SECRETS,
                         RCE_HEAPDUMP_ANALYSIS, RCE_ROUTE_EXPOSURE_CONSOLES)
    return {
        "leads": ACCESS_CONTROL_ROUTE_EXPOSURE_LEADS,
        "browser": ACCESS_CONTROL_ROUTE_EXPOSURE_BROWSER_LEADS,
        "exposed_files": PATH_TRAVERSAL_EXPOSED_FILES.format(git_reconstruct="DISABLED",
                                                             validate_secrets="DISABLED"),
        "git": PATH_TRAVERSAL_GIT_RECONSTRUCT,
        "validate": PATH_TRAVERSAL_VALIDATE_SECRETS,
        "consoles": RCE_ROUTE_EXPOSURE_CONSOLES.format(heapdump_analysis="DISABLED"),
        "heapdump": RCE_HEAPDUMP_ANALYSIS,
    }


@pytest.mark.parametrize("name", ["leads", "browser", "exposed_files", "git", "validate", "consoles", "heapdump"])
def test_every_part_names_real_tools_only_and_no_em_dash(name):
    text = _new_parts()[name]
    assert "—" not in text
    named = set(re.findall(r"\b(execute_[a-z_]+|fs_[a-z]+|job_spawn|kali_shell|query_graph|graph_summary|"
                           r"proxy_brain|switch_skill)\b", text))
    assert named <= REAL_TOOLS, named - REAL_TOOLS
    assert "{" not in re.sub(r"\{[^{}]*\}", "", text) or "MATCH" in text


@pytest.mark.parametrize("name", ["leads", "browser", "exposed_files", "consoles"])
def test_main_parts_carry_the_contract(name):
    text = _new_parts()[name]
    # A bounded, ordered pull of route_exposure nodes.
    assert "source:'route_exposure'" in text and "ORDER BY" in text and "LIMIT 50" in text
    # The record contract: the proof type with the exact id, in the same response, then verified.
    assert "vulnerability_confirmed" in text and "related_finding_ids" in text
    assert "IN THE SAME RESPONSE" in text
    assert "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {id:'<ID>'})" in text
    assert "NEVER put ids on `exploit_success`" in text
    # A live campaign lost a proven lead the model wrote as "Record X" in
    # actionable_findings, so the contract says where a confirmation must go.
    assert "records NOTHING" in text and "Only a `chain_findings` entry" in text
    assert "before any `switch_skill` or `transition_phase`" in text
    # A live session with access_control off confirmed every lead from rce; the
    # writer refuses that now, and the part says so before the model tries.
    assert "confirmed ONLY in the access_control\n  skill" in text
    # The rejection rule and the forbidden actions.
    assert "gets NO entry at all" in text
    for forbidden in ("never POST to any `/actuator/*` path", "springboot-env-rce-chains",
                      "never guess or compute a PIN", "No form submit, no"):
        assert forbidden in text
    # Values stay in files, with the banned curl flags.
    assert "/tmp/rex-<id>-anon.body" in text
    assert "`-v`, `-i`, `--trace`, `-D -` and `-o -` are" in text


def test_a_declared_login_is_proof_without_sensitive_content():
    row = next(line for line in _new_parts()["leads"].splitlines() if line.startswith("| internal_api"))
    proof, reject = row.split(" | ")[1], row.split(" | ")[2]
    # A live run rejected an OpenAPI-locked export for "nothing sensitive": the
    # API's own declaration (or locked siblings) is the proof; the sensitivity
    # rejection holds only for a lead with none of those signals.
    assert "the content need not be sensitive" in proof
    # The query computes the signal, so the model reads one boolean, not list semantics.
    assert "`login_declared` is true" in proof and reject.startswith("`login_declared` is false")
    assert "['openapi', 'siblings_locked', 'version_locked', 'vary_auth']) AS login_declared" in _new_parts()["leads"]


def test_a_lead_is_reread_with_the_same_cypher_never_in_plain_english():
    # A live run re-asked "return ... expected ..." in plain English; the
    # text-to-Cypher step read a property that does not exist and the model
    # rejected two true leads on the None it got back.
    for name in ("leads", "exposed_files", "consoles"):
        text = _new_parts()[name]
        assert "re-run THIS query with `AND v.id IN ['<id>', ...]`" in text
        assert "`expected` is the alias of `v.auth_expected_by`" in text


def test_no_clone_and_no_full_backup_in_any_phase():
    # In a live exploitation turn the generic workflow tried `git clone` with the
    # reconstruct switch off and downloaded a 5 MB backup in full.
    text = _new_parts()["exposed_files"]
    assert "In EVERY phase, the exploitation phase included" in text
    assert "never `git clone`" in text and "never download a backup archive in\nfull" in text


def test_bodies_left_behind_are_removed_before_leaving_the_skill():
    for name in ("leads", "exposed_files", "consoles"):
        assert "removes every `/tmp/rex-*` file still there" in _new_parts()[name]


def test_an_uploaded_file_is_proven_by_a_link_only_the_session_sees():
    row = next(line for line in _new_parts()["leads"].splitlines() if line.startswith("| uploaded_content"))
    # "A logged-in page links to it" is a check the agent runs, not a judgement:
    # the root fetched both ways, the file's path counted in each body.
    assert "fetch the site root anonymously and with `use_session=true`" in row
    assert "in the logged-in body only" in row
    assert "the anonymous root links it too" in row


def test_the_handoff_names_only_path_traversal_and_rce():
    text = _new_parts()["leads"]
    targets = set(re.findall(r"to_skill: '([a-z_]+)'", text)) | set(re.findall(r"switch to `([a-z_]+)`", text))
    assert targets == {"path_traversal", "rce"}
    from state import KNOWN_ATTACK_PATHS
    assert targets <= set(KNOWN_ATTACK_PATHS)


def test_exploitation_only_steps_say_so():
    parts = _new_parts()
    assert "EXPLOITATION phase only" in parts["leads"]
    assert "EXPLOITATION phase" in parts["git"] and "EXPLOITATION phase" in parts["heapdump"]
    assert "Unlocked (EXPLOITATION phase)" in parts["consoles"]


def test_one_git_walk_proves_every_vcs_finding_and_head_alone_does_not():
    # A live AG5 "proved" .git/HEAD and .git/config by their own bodies, never
    # fetching the ref or an object.
    text = _new_parts()["exposed_files"]
    row = next(line for line in text.splitlines() if line.startswith("| vcs_exposure (.git)"))
    assert "`/.git/HEAD` and `/.git/config`" in row
    assert "HEAD and config alone prove nothing" in row
    assert "one walk proves every vcs_exposure finding of that base URL" in row


def test_exploitation_only_steps_ask_for_the_phase():
    # Live sessions in the informational phase completed without the gated step,
    # since no part said to request the phase it needs.
    flat = {name: " ".join(text.split()) for name, text in _new_parts().items()}
    for name in ("git", "heapdump", "consoles", "leads"):
        assert "request `transition_phase` to exploitation naming" in flat[name] or \
            "request `transition_phase` naming that one request" in flat[name], name


def test_validation_runs_whenever_its_switch_is_on():
    text = _new_parts()["exposed_files"]
    assert "When secret validation is ENABLED:" in text
    assert "one identity call per key, before you complete" in text


def test_reconstruction_is_mandatory_when_enabled():
    # A live AG6 recorded the minimal .git proof + validation and completed without
    # reconstructing, because the always-present block only said what DISABLED means.
    flat = " ".join(_new_parts()["exposed_files"].split())
    assert "When git reconstruction is ENABLED: proving an exposed `.git` includes reconstructing it this run" in flat
    assert "do not complete the session while the reconstruction is still pending" in flat


def test_an_anonymous_replay_uses_proxy_brain_and_prints_no_body():
    # A live AG10 re-requested the exports with curl and never exercised the replay.
    text = _new_parts()["leads"]
    assert "`redamon.replay(<txn id>, anonymous=True)`" in text
    assert "`<Response <status> <length>b anonymous>`" in text
    assert "never `.body`" in text
    # A live AG10's replay was refused in the informational phase and it fell back
    # to the curl pair, whose logged-in side carried the profile's header.
    flat = " ".join(text.split())
    assert "A replay is an EXPLOITATION-phase request" in flat
    assert "send only that anonymous side: no logged-in request goes with it" in flat


def test_the_ui_diff_is_a_real_render():
    # A live AG11 fetched the page with curl: no script ran, no sub-resource loaded.
    text = _new_parts()["leads"]
    assert "`b = redamon.browser(<id of a" in text and "`b.goto('<page path>')`" in text
    assert "A curl of the page is not a render" in text
    # A live AG11 curled /profile, hit the login redirect and POSTed /login 118 times.
    flat = " ".join(text.split())
    assert "logged in through the engagement's session, so you never submit the login form" in flat
    assert "NEVER submit a login form, POST credentials, or loop authentication" in flat


def test_an_exposed_files_request_covers_the_whole_pull():
    # A live AG5 proved only the .git and .env the prompt named.
    assert "covers every finding this pull returns" in _new_parts()["exposed_files"]


def test_the_reconstructed_tree_is_never_printed():
    # A live AG6 "reviewed the source" by printing every recovered file.
    flat = " ".join(_new_parts()["git"].split())
    assert "The reconstructed tree is never printed" in flat
    assert "not even to review the source" in flat


def test_the_console_evaluation_is_one_request_and_no_retry():
    # A live run retried the evaluation seven times, with POSTs.
    flat = " ".join(_new_parts()["consoles"].split())
    assert "It is exactly ONE GET: never a POST, an OPTIONS or a retry" in flat
    assert "no method-support probe before or after it" in flat
    assert "evaluation unconfirmed and stop there" in flat
    assert "Never send a POST or an OPTIONS to any of them, not even to probe" in flat


def test_a_console_lock_is_read_from_evalex_trusted_alone():
    # A live AG8b counted `__debugger__` as a PIN prompt and called an unlocked console locked.
    flat = " ".join(_new_parts()["consoles"].split())
    assert "`EVALEX = true` with `EVALEX_TRUSTED = false` is locked" in flat
    assert "Unlocked (EXPLOITATION phase), `EVALEX_TRUSTED = true`" in flat
    assert "A Werkzeug console's lock is `EVALEX_TRUSTED` and nothing else" in flat
    assert "`__debugger__`" in flat and "none of them means locked" in flat


def test_the_console_evaluation_is_the_bare_expression_and_a_400_ends_it():
    # A live AG8b sent `print(1+1)`, met a 400, and retried the shape twice more.
    flat = " ".join(_new_parts()["consoles"].split())
    assert "?__debugger__=yes&cmd=1%2B1&frm=<frm>&s=<SECRET>" in flat
    assert "`cmd` is the bare expression `1+1`, never `print(1+1)` or any other wrapper" in flat
    assert "a 400 ends the proof, it never means the request shape needs another try" in flat


def test_the_console_secret_is_the_script_variable_and_never_guessed():
    # A live AG8b looked for SECRET in form inputs, found none, and sent without it.
    flat = " ".join(_new_parts()["consoles"].split())
    assert 'the page\'s `SECRET = "..."` script variable (beside `EVALEX`, not a form field)' in flat
    assert "`frm` is `0` on the standalone console" in flat
    assert "never prints it, and sends nothing when it is missing" in flat


def test_the_browser_part_proves_each_v2_lead_its_own_way():
    flat = " ".join(_new_parts()["browser"].split())
    # The pull takes the v2 kinds and the client-gated leads L1 also returns.
    assert "v.exposure_kind IN ['cors_misconfig', 'auth_cacheable']" in flat
    assert "v.route_class = 'client_gated'" in flat and "prove those with B4, not with L2-L3" in flat
    # CORS: four origins, logged in, headers to a file; proof needs credentials AND a sensitive body.
    for origin in ("https://evil.invalid", "`null`", "https://<host>.evil.invalid", "https://evil<registrable domain>"):
        assert origin in flat
    # Headers go to a file: `-D -` would echo the session (the shared rules forbid it).
    assert "-D /tmp/rex-<id>-<n>.hdr" in flat
    assert "a `*` origin without credentials" in flat and "evidence/cors-<id>.html" in flat
    assert "never served, never opened" in flat
    # Cache: a unique buster, logged-in then anonymous on the same URL, never PURGE.
    assert "?rdmncb=<12 random hex>" in flat and "never send PURGE" in flat and "never reuse a buster" in flat
    # Client-side gating: an anonymous render, then the pair; a 401 API is correct, not a finding.
    assert "execute_playwright, which never carries the session" in flat
    assert "client-side hiding with server-side enforcement is correct" in flat


def test_the_browser_part_finds_the_hidden_pages_in_the_graph_never_by_guessing():
    """REGRESSION (AG16-17, first run): told only to open "the router page that calls the
    lead's API", the agent guessed /admin from /api/admin/stats, got the server's redirect
    to the login page and never rendered the real client-side page. The pages recon read
    from the same bundle are in the graph; B4 now reads them first."""
    flat = " ".join(_new_parts()["browser"].split())
    assert "v.path AS path" in flat
    assert ("MATCH (f:JsReconFinding {finding_type:'js_file'})-[:HAS_ENDPOINT]->"
            "(api:Endpoint {path:'<path>'})") in flat
    assert "MATCH (f)-[:HAS_ENDPOINT]->(page:Endpoint {endpoint_type:'route'})" in flat
    assert "Never guess a page from the API's path." in flat
    assert "go to each page from step 1" in flat


def test_the_browser_part_makes_the_render_part_of_the_proof():
    """REGRESSION (AG16-17, second run): with the pages found, the agent skipped the render
    and confirmed /api/admin/stats on the anonymous / logged-in pair alone. That pair is L2's
    proof of an anonymous API; client-side gating also needs the page that fired it."""
    flat = " ".join(_new_parts()["browser"].split())
    assert "Proof needs BOTH: a page rendered without the session fired the API (step 2)" in flat
    assert "Name that page in the evidence." in flat
    assert "without the render the lead stays unproven, so never skip step 2" in flat


def test_the_lead_query_follows_jevs_reading_and_demotes_walls_and_public_content():
    """Recon writes Jev's opinions onto the leads; the pull reads them in the same order
    recon put them in (route_exposure scanner._order_leads): most sensitive first, a
    confident wall page or public-content reading last. Never a filter: no lead drops."""
    from prompts.route_exposure_shared import candidate_query
    query = candidate_query(["anonymous_access", "sensitive_data"])
    order = query[query.index("ORDER BY"):query.index("LIMIT 50")]
    assert order.index("anon_page_class IN ['login_only', 'parked', 'default', 'placeholder', 'error']") \
        < order.index("coalesce(v.route_jev_sensitivity, -1) DESC")
    assert "coalesce(v.anon_page_class_confidence, 0) >= 70" in order
    assert "v.route_jev_kind = 'public_content'" in order
    assert "coalesce(v.route_jev_kind_confidence, 0) >= 70" in order
    where = query[query.index("WHERE"):query.index("RETURN")]
    assert "jev" not in where and "page_class" not in where
    assert "v.route_jev_kind AS jev_kind, v.anon_page_class AS page_class" in query
    assert "never prove or reject a lead on their own" in query
