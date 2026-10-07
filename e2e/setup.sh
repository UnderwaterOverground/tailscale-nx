#!/usr/bin/env bash
# Brings up the local tailnet and writes a reusable pre-auth key to
# state/authkey. Idempotent; re-run after `down.sh` for a fresh tailnet.
set -euo pipefail
cd "$(dirname "$0")"
./gen-certs.sh
mkdir -p state/headscale state/peer

docker compose up -d --wait headscale
hs() { docker compose exec -T headscale headscale "$@"; }

hs users create tsnx >/dev/null 2>&1 || true
user_id=$(hs users list -o json | python3 -c 'import json,sys; print(next(u["id"] for u in json.load(sys.stdin) if u["name"]=="tsnx"))')
if [[ ! -s state/authkey ]]; then
  hs preauthkeys create --user "$user_id" --reusable --expiration 720h -o json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])' > state/authkey
fi

docker compose --profile peer up -d peer echo web iperf
for _ in $(seq 30); do
  docker compose exec -T peer tailscale ip -4 >/dev/null 2>&1 && break
  sleep 1
done
echo "headscale: https://headscale (host: https://127.0.0.1:8443), CA: e2e/state/certs/ca.der"
echo "auth key:  $(cat state/authkey)"
echo "peer1:     $(docker compose exec -T peer tailscale ip -4)"
