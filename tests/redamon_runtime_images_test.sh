#!/usr/bin/env bash
# =============================================================================
# `clean` / `purge` remove every recon tool image a scan can pull (drift-map #21).
#
# remove_redamon_images used to carry its own list, which removed two images
# nothing pulls (dnsx, trufflehog) and left tlsx, graphql-cop and zaproxy behind.
# It now reads recon/entrypoint.sh's IMAGES; this checks that list against the
# *_DOCKER_IMAGE defaults in recon/project_settings.py, the images a scan runs.
#
# Pure unit test: `docker` is stubbed as a bash function, so it runs anywhere
# with no Docker daemon.  Run:  bash tests/redamon_runtime_images_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"   # BASH_SOURCE guard blocks command dispatch
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

listed="$(_recon_tool_images)"

# Every third-party image a scan runs, by its default.
defaults="$(sed -n "s/^[[:space:]]*'[A-Z0-9_]*_DOCKER_IMAGE':[[:space:]]*'\([^']*\)'.*/\1/p" \
    "$REPO_ROOT/recon/project_settings.py" | grep -v '^redamon-' | sort -u)"

if [[ "$(printf '%s\n' "$defaults" | grep -c .)" -ge 10 ]]; then
  pass "parsed the *_DOCKER_IMAGE defaults"
else
  fail "parsed only: $defaults"
fi

while IFS= read -r img; do
  [[ -z "$img" ]] && continue
  if printf '%s\n' "$listed" | grep -qxF "$img"; then
    pass "removed: $img"
  else
    fail "a scan pulls $img but remove_redamon_images leaves it"
  fi
done <<< "$defaults"

if printf '%s\n' "$listed" | grep -q '^redamon-'; then
  fail "locally built redamon-* images belong to the first rmi pass"
else
  pass "no redamon-* image in the pulled list"
fi

removed=""
docker() { [[ "$1" == "rmi" ]] && removed="$removed $2"; return 0; }
LOCAL_LLM_IMAGE="ollama/ollama:test"
remove_redamon_images >/dev/null 2>&1
for img in projectdiscovery/tlsx:latest dolevf/graphql-cop:1.14 ghcr.io/zaproxy/zaproxy:stable ollama/ollama:test; do
  if [[ " $removed " == *" $img "* ]]; then pass "rmi $img"; else fail "rmi $img not called"; fi
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
