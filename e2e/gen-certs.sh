#!/usr/bin/env bash
# Creates a throwaway CA and a server cert for "headscale" (control + DERP).
# Clients trust state/certs/ca.pem (tailscale: SSL_CERT_FILE, tsnx: TSNX_EXTRA_ROOT).
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/state/certs"
mkdir -p "$dir"
cd "$dir"
[[ -f headscale.pem ]] && exit 0

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.pem -days 3650 -subj "/CN=tsnx e2e CA" 2>/dev/null
openssl x509 -in ca.pem -outform der -out ca.der
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout headscale.key -out headscale.csr -subj "/CN=headscale" 2>/dev/null
printf "subjectAltName=DNS:headscale,IP:172.30.0.10\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in headscale.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out headscale.pem -days 3650 -extfile ext.cnf 2>/dev/null
chmod 644 ./*.pem ./*.key
echo "generated certs in $dir"
