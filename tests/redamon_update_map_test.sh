#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` rebuilds every image whose baked files changed.
#
# The changed-file -> service map (_map_core_changes, _map_tool_changes and
# _map_baked_graph_db) is the only thing that decides whether an update rebuilds
# a service. A path it does not cover is updated on disk and silently NOT in the
# running container: mcp/requirements.txt and kali's other baked files, and
# recon_settings/ in the recon image, were such paths (drift-map #7).
#
# So the expectations are DERIVED, not typed here: every COPY/ADD source of every
# service docker-compose.yml builds (and its Dockerfile) must make the map rebuild
# that service's image, or at least restart the service when a compose bind mount
# shadows the baked copy. A hand list of expected rules is what let the map's
# mistakes pass before (drift-map #30). What no Dockerfile can express, the
# orchestrator caching modules it imports from its mounts, stays explicit below.
#
# Hermetic: sources redamon.sh and reads the tracked files, no Docker. Needs
# python3 with PyYAML and git; skips cleanly without them. Run:
#   bash tests/redamon_update_map_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass; else fail "$1 (got='$2' expected='$3')"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' 2>/dev/null \
    || ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    echo "  SKIP  needs python3 with PyYAML and a git checkout"
    exit 0
fi

# Images whose sources the ORCHESTRATOR mounts into each scan container it spawns
# (recon_orchestrator/container_manager.py), so a source change reaches the next
# scan without a rebuild; only the Dockerfile and requirements are baked for real.
# "<service> <repo path prefix> <container path container_manager.py binds it at>"
SPAWN_MOUNTED=(
    "ai-attack-surface scanners/ai_attack_surface_scan/ /app/ai_attack_surface_scan"
    "supply-chain scanners/supply_chain_scan/ /app/supply_chain_scan"
)

# everything one changed file makes `update` do: "<built services> | <restarted>"
effect() {
    local rebuild_core=() restart_only=() rebuild_tools=()
    local rebuild_capture=false rebuild_plugins=false
    _map_core_changes "$1"
    _map_tool_changes "$1"
    [[ "$rebuild_capture" == "true" ]] && rebuild_tools+=(capture-proxy traffic-ingest)
    [[ "$rebuild_plugins" == "true" ]] && rebuild_tools+=(plugin-runner plugin-gateway)
    echo " ${rebuild_core[*]-} ${rebuild_tools[*]-} | ${restart_only[*]-} "
}

section "every file an image bakes rebuilds it"
read -r -d '' PY <<'PYEOF'
import fnmatch, json, os, re, subprocess, sys
import yaml

root = sys.argv[1]
doc = yaml.safe_load(open(os.path.join(root, "docker-compose.yml")))
project = doc.get("name") or os.path.basename(root).lower()
tracked = [f for f in subprocess.run(["git", "-C", root, "ls-files"], capture_output=True,
                                     text=True, check=True).stdout.split("\n") if f]
BUILD_NAMES = re.compile(r"(Dockerfile|requirements[^/]*|constraints[^/]*|entrypoint[^/]*|package(-lock)?\.json)$")


def sample(paths):
    """Every build-relevant file name, plus one file per directory down to three
    levels: the update map's rules are path prefixes no deeper than that and a few
    file names, so this probes every rule without probing every file."""
    seen, out = set(), []
    for f in sorted(paths):
        key = "/".join(os.path.dirname(f).split("/")[:3])
        if BUILD_NAMES.search(f) or key not in seen:
            out.append(f)
            seen.add(key)
    return out


for svc, spec in doc["services"].items():
    build = spec.get("build")
    if not build:
        continue
    ctx, df = (build, "Dockerfile") if isinstance(build, str) else (build.get("context", "."), build.get("dockerfile", "Dockerfile"))
    ctx = os.path.normpath(ctx)
    image = (spec.get("image") or f"{project}-{svc}").split(":")[0]
    print(f"IMAGE\t{svc}\t{image}")
    dockerfile = os.path.normpath(os.path.join(ctx, df))
    sources = {dockerfile}
    text = re.sub(r"\\\n", " ", open(os.path.join(root, dockerfile), encoding="utf-8").read())
    for line in text.splitlines():
        m = re.match(r"\s*(COPY|ADD)\s+(.+)", line, re.I)
        if not m or "--from" in m.group(2):
            continue
        args = m.group(2).strip()
        parts = json.loads(args) if args.startswith("[") else [a for a in args.split() if not a.startswith("--")]
        for src in parts[:-1]:
            sources.add(os.path.normpath(os.path.join(ctx, src)))
    named, under_dirs = set(), set()
    for src in sources:
        for f in tracked:
            if f == src or fnmatch.fnmatch(f, src):
                named.add(f)
            elif src == "." or f.startswith(src + "/"):
                under_dirs.add(f)
    for f in sorted(named | set(sample(under_dirs - named))):
        print(f"COPY\t{svc}\t{f}")
    for vol in spec.get("volumes") or []:
        host = vol.split(":")[0] if isinstance(vol, str) else vol.get("source", "")
        if host.startswith("./"):
            print(f"BIND\t{svc}\t{os.path.normpath(host)}")
PYEOF
listing="$(python3 -c "$PY" "$REPO_ROOT")" || { fail "could not read the compose build graph"; listing=""; }

declare -A image_of=()
binds=()
copies=()
while IFS=$'\t' read -r kind svc path; do
    case "$kind" in
        IMAGE) image_of[$svc]="$path" ;;
        BIND)  binds+=("$svc $path") ;;
        COPY)  copies+=("$svc $path") ;;
    esac
done <<< "$listing"

assert_eq "the compose file builds at least the core and tool images" \
    "$([[ ${#image_of[@]} -ge 15 && ${#copies[@]} -ge 100 ]] && echo yes)" "yes"

shadowed_by_bind() {   # <service> <file>
    local b
    for b in "${binds[@]}"; do
        [[ "${b%% *}" == "$1" ]] || continue
        [[ "$2" == "${b#* }" || "$2" == "${b#* }/"* ]] && return 0
    done
    return 1
}

spawn_mounted() {      # <service> <file>
    local m
    [[ "$(basename "$2")" =~ ^(Dockerfile|.*requirements.*)$ ]] && return 1
    local svc prefix _bind
    for m in "${SPAWN_MOUNTED[@]}"; do
        read -r svc prefix _bind <<< "$m"
        [[ "$svc" == "$1" && "$2" == "$prefix"* ]] && return 0
    done
    return 1
}

for entry in "${copies[@]}"; do
    svc="${entry%% *}" file="${entry#* }"
    out="$(effect "$file")"
    built="${out%%|*}" restarted="${out#*|}"
    rebuilt=false
    for other in $built; do
        [[ "${image_of[$other]-}" == "${image_of[$svc]}" ]] && rebuilt=true
    done
    if [[ "$rebuilt" == "true" ]]; then
        pass
    elif shadowed_by_bind "$svc" "$file" && [[ "$restarted" == *" $svc "* ]]; then
        pass
    elif spawn_mounted "$svc" "$file"; then
        pass
    else
        fail "$svc bakes $file, but a release changing it does not rebuild $svc (built:$built restarted:$restarted)"
    fi
done

for m in "${SPAWN_MOUNTED[@]}"; do
    read -r _svc prefix bind <<< "$m"
    assert_eq "container_manager.py binds ${prefix%/} at $bind" \
        "$(grep -cF "{\"bind\": \"$bind\", \"mode\"" "$REPO_ROOT/recon_orchestrator/container_manager.py" | awk '{print ($1 > 0) ? "yes" : "no"}')" "yes"
done

section "graph_db/ goes only to the images that bake it"
tools() {
    local rebuild_tools=()
    [[ -n "${2-}" ]] && read -ra rebuild_tools <<< "$2"
    _map_baked_graph_db "$1"
    echo "tools=${rebuild_tools[*]-}"
}
assert_eq "the supply-chain images mount graph_db rather than bake it" \
    "$(tools 'graph_db/mixins/base_mixin.py')" "tools=recon vuln-scanner github-secret-hunter"
assert_eq "an image the release already rebuilds is not queued twice" \
    "$(tools 'graph_db/mixins/base_mixin.py' 'recon vuln-scanner')" "tools=recon vuln-scanner github-secret-hunter"
assert_eq "without a graph_db/ change nothing is added" \
    "$(tools $'recon/main.py\nagentic/api.py' 'wcvs')" "tools=wcvs"

section "the orchestrator caches what it imports from its mounts (not in any Dockerfile)"
map() {
    local rebuild_core=() restart_only=()
    _map_core_changes "$1"
    echo "rebuild=${rebuild_core[*]-} restart=${restart_only[*]-}"
}
assert_eq "recon_settings/ restarts it" "$(map 'recon_settings/registry.json')" \
    "rebuild=agent restart=recon-orchestrator"
assert_eq "graph_db/ restarts it" "$(map 'graph_db/mixins/recon/triage_mixin.py')" \
    "rebuild=agent restart=recon-orchestrator"
assert_eq "recon/project_settings.py restarts it (it serves /defaults)" \
    "$(map 'recon/project_settings.py')" "rebuild= restart=recon-orchestrator"
assert_eq "recon/settings_registry.py does the same" \
    "$(map 'recon/settings_registry.py')" "rebuild= restart=recon-orchestrator"
assert_eq "an orchestrator rebuilt anyway is not restarted as well" \
    "$(map $'graph_db/mixins/base_mixin.py\nrecon_orchestrator/Dockerfile')" "rebuild=recon-orchestrator agent restart="
assert_eq "docs and tests rebuild and restart nothing" \
    "$(effect $'docs/readmes/README.md\ntests/test_x.py\nskills/a/SKILL.md' | tr -d ' ')" "|"

section "cmd_update runs every map"
assert_eq "_map_core_changes" "$(grep -c '^        _map_core_changes "$changed_files"$' "$REPO_ROOT/redamon.sh")" "1"
assert_eq "_map_tool_changes" "$(grep -c '^    _map_tool_changes "$changed_files"$' "$REPO_ROOT/redamon.sh")" "1"

echo ""
echo "PASS: $PASS  FAIL: $FAIL"
[[ $FAIL -eq 0 ]]
