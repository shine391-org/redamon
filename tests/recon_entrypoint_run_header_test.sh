#!/usr/bin/env bash
# =============================================================================
# recon/entrypoint.sh names its run to the Docker broker (plan 12.4).
#
# The broker labels each tool container with the run in the X-Redamon-Run
# header, so a stop or a pause reaches one run's tools only. The entrypoint
# writes that header into the Docker CLI's config.json (HttpHeaders) and exports
# DOCKER_CONFIG for the pipeline it execs. The block is cut out of the entrypoint
# (banner to banner) and run with its directory moved into a sandbox.
#   bash tests/recon_entrypoint_run_header_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="$REPO_ROOT/recon/entrypoint.sh"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

BLOCK="$(awk '/^# Name this run to the Docker broker/{on=1} /^# Check Docker Socket Access/{on=0} on' "$ENTRYPOINT")"
if [[ "$BLOCK" != *'DOCKER_CONFIG=/run/redamon-docker'* ]]; then
    echo "run-header block not found in $ENTRYPOINT"
    exit 1
fi
BLOCK="${BLOCK//\/run\/redamon-docker/$SANDBOX/cfg}"

# Runs the block under `set -e` like the entrypoint, then prints what the
# pipeline would inherit: DOCKER_CONFIG and the config file.
run_block() {
    rm -rf "$SANDBOX/cfg"
    env -i PATH="$PATH" "$@" bash -c '
        set -e
        RED=""; GREEN=""; YELLOW=""; NC=""
        eval "$1" >/dev/null
        echo "DOCKER_CONFIG=${DOCKER_CONFIG:-}"
        [ -f "${DOCKER_CONFIG:-/nonexistent}/config.json" ] && cat "$DOCKER_CONFIG/config.json"
        true
    ' _ "$BLOCK" 2>/dev/null
}

PROJECT=cmproj0123456789abc
RUN=6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d

out="$(run_block PROJECT_ID=$PROJECT RECON_RUN_ID=$RUN)"
assert_eq "full recon exports DOCKER_CONFIG" "$(sed -n 1p <<<"$out")" "DOCKER_CONFIG=$SANDBOX/cfg"
assert_eq "full recon header" "$(sed -n 2p <<<"$out")" \
    "{\"HttpHeaders\": {\"X-Redamon-Run\": \"full_recon:$PROJECT:$RUN\"}}"
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$SANDBOX/cfg/config.json" 2>/dev/null; then
    pass "config.json is valid JSON"
else
    fail "config.json is valid JSON"
fi

out="$(run_block PROJECT_ID=$PROJECT RECON_RUN_ID=other PARTIAL_RECON_RUN_ID=$RUN)"
assert_eq "a partial run names itself partial_recon" "$(sed -n 2p <<<"$out")" \
    "{\"HttpHeaders\": {\"X-Redamon-Run\": \"partial_recon:$PROJECT:$RUN\"}}"

out="$(run_block PROJECT_ID=$PROJECT)"
assert_eq "no run id: no header, DOCKER_CONFIG untouched" "$out" "DOCKER_CONFIG="

out="$(run_block PROJECT_ID='p1"}}' RECON_RUN_ID=$RUN)"
assert_eq "a project id that would break the JSON writes nothing" "$out" "DOCKER_CONFIG="

out="$(run_block PROJECT_ID=$PROJECT RECON_RUN_ID='r1:full_recon')"
assert_eq "a run id with the separator writes nothing" "$out" "DOCKER_CONFIG="

if grep -qE '/tmp/redamon|/app/recon' <<<"$(awk '/^# Name this run to the Docker broker/{on=1} /^# Check Docker Socket Access/{on=0} on' "$ENTRYPOINT" | grep 'DOCKER_CONFIG=')"; then
    fail "the config directory is not a shared host bind"
else
    pass "the config directory is not a shared host bind"
fi

echo
echo "run header: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
