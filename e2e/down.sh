#!/usr/bin/env bash
# Stops the local tailnet and deletes its state (keys, DB, certs).
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile peer down -v
rm -rf state
