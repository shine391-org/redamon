#!/usr/bin/env bash
# =============================================================================
# A stop during recon/entrypoint.sh's image pulls ends the container at once
# (plan 12.3).
#
# Bash is PID 1 in the recon container until the entrypoint execs Python, and
# PID 1 gets no default action for a signal it has no trap for, so a stop then
# waited out the orchestrator's whole grace. The entrypoint now traps TERM, and
# runs its long commands as `cmd & wait $!` (bash runs a trap only between
# commands). The trap line and the pull block are cut out of the entrypoint and
# run as PID 1 of a new PID namespace (`unshare -rpf`), with `docker pull`
# stubbed to hang; no Docker daemon is needed.
#   bash tests/recon_entrypoint_stop_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${STOP_ENTRYPOINT:-$REPO_ROOT/recon/entrypoint.sh}"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

if ! unshare -rpf true 2>/dev/null; then
    echo "SKIP: this host refuses an unprivileged PID namespace (unshare -rpf)"
    exit 0
fi

TRAP="$(grep -E "^trap '.*' TERM$" "$ENTRYPOINT" || true)"
PULLS="$(awk '/^# Pull required Docker images/{on=1} /^# Execute the command/{on=0} on' "$ENTRYPOINT")"
if [[ "$PULLS" != *'docker pull'* ]]; then
    echo "pull block not found in $ENTRYPOINT"
    exit 1
fi

STUBS='
RED=""; GREEN=""; YELLOW=""; NC=""
docker() {
    case "$1" in
        images) return 0 ;;          # nothing pulled yet
        pull)   sleep 30 ;;          # a slow registry
    esac
}
'

# Starts `body` as PID 1 of a new namespace. Sets OUTER (the unshare process,
# this shell's child) and INNER (that PID 1, as the host sees it).
start_as_pid1() {
    unshare -rpf bash -c "set -e; $1" >/dev/null 2>&1 &
    OUTER=$!
    INNER=""
    local i
    for i in $(seq 1 50); do
        INNER="$(awk '{print $1}' "/proc/$OUTER/task/$OUTER/children" 2>/dev/null)"
        [[ -n "$INNER" ]] && break
        sleep 0.1
    done
    sleep 0.5   # let it reach the first pull
}

# --- the entrypoint as it is: TERM ends it at once, with 143 -----------------
start_as_pid1 "$STUBS
$TRAP
$PULLS"
started=$(date +%s)
kill -TERM "$INNER" 2>/dev/null
# An entrypoint that ignores the stop would run every stubbed pull (minutes).
( sleep 5; kill -KILL "$INNER" 2>/dev/null ) &
WATCHDOG=$!
wait "$OUTER"; rc=$?
kill "$WATCHDOG" 2>/dev/null; wait "$WATCHDOG" 2>/dev/null
elapsed=$(( $(date +%s) - started ))
if [[ -n "$TRAP" ]]; then pass "the entrypoint traps TERM"; else fail "the entrypoint traps TERM"; fi
if [[ $rc -eq 143 ]]; then pass "a stop during a pull exits 143"; else fail "a stop during a pull exits 143 (got $rc)"; fi
if [[ $elapsed -le 3 ]]; then pass "within 3 s, not after the pull (${elapsed}s)"; else fail "within 3 s (took ${elapsed}s)"; fi

# --- control: without the trap, PID 1 ignores TERM (what the test relies on) --
start_as_pid1 "$STUBS
$PULLS"
kill -TERM "$INNER" 2>/dev/null
sleep 1.5
if kill -0 "$OUTER" 2>/dev/null; then
    pass "control: an untrapped PID 1 ignores TERM"
else
    fail "control: an untrapped PID 1 ignores TERM (it exited, so this test proves nothing)"
fi
kill -KILL "$INNER" 2>/dev/null; wait "$OUTER" 2>/dev/null

# --- the trap is cleared before Python takes over ------------------------------
if awk '/^trap - TERM$/{t=NR} /^exec "\$@"$/{e=NR} END{exit !(t && e && t < e)}' "$ENTRYPOINT"; then
    pass "the trap is reset before exec"
else
    fail "the trap is reset before exec"
fi

echo
echo "entrypoint stop: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
