#!/usr/bin/env bash
# Start the lab on redamon-network and redamon_pentest-net, whatever /16 Docker
# gave each: the services take <prefix>.93-.96 of each network's own subnet.
set -euo pipefail
cd "$(dirname "$0")"
prefix_of() {
  docker network inspect "$1" --format '{{(index .IPAM.Config 0).Subnet}}' | cut -d. -f1-3
}
export LAB_NET_PREFIX="$(prefix_of redamon-network)"
export PENTEST_NET_PREFIX="$(prefix_of redamon_pentest-net)"
echo "lab on ${LAB_NET_PREFIX}.93-.96 (redamon-network) and ${PENTEST_NET_PREFIX}.93-.96 (redamon_pentest-net)"
docker compose up -d --build "$@"
