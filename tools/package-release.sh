#!/usr/bin/env bash
# Builds a release zip in dist/: the files to extract to the SD card root
# (sysmodule with its boot2 flag, overlay, example config). Usage:
#   tools/package-release.sh        (or: make release)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
for f in switch/overlay/Makefile; do
  grep -q "APP_VERSION.*:=.*$version" "$f" || { echo "$f: APP_VERSION is not $version"; exit 1; }
done
grep -q "\"version\": \"$version\"" switch/sysmodule/res/app.json || { echo "app.json: version is not $version"; exit 1; }

# The overlay's version is a compiler flag, which make doesn't track: drop
# its object and metadata so they rebuild. Done inside a container, as are
# the checks below: Docker on macOS can show the build a stale view of files
# changed on the host (timestamps, deleted files).
in_docker() { docker run --rm -v "$root:/src" -w /src alpine sh -c "$1"; }
in_docker 'rm -f switch/overlay/build/main.o switch/overlay/tailscale-nx.nacp switch/overlay/tailscale-nx.ovl'
make sysmodule overlay >/dev/null
in_docker "grep -a -q 'tailscale-nx $version' switch/overlay/tailscale-nx.elf" || { echo "overlay doesn't say $version"; exit 1; }
# The NACP holds the name, author and version Ultrahand shows.
nacp_has() { in_docker "tr '\\000' '\\n' < switch/overlay/tailscale-nx.nacp | grep -q -F '$1'"; }
in_docker "[ \$(wc -c < switch/overlay/tailscale-nx.nacp) -eq 16384 ]" && nacp_has "$version" && nacp_has UnderwaterOverground ||
  { echo "switch/overlay/tailscale-nx.nacp is stale or malformed"; exit 1; }
contents=switch/sysmodule/dist/atmosphere/contents/4200000000005453
for f in "$contents/exefs.nsp" "$contents/toolbox.json" "$contents/flags/boot2.flag" switch/overlay/tailscale-nx.ovl; do
  [[ -f "$f" ]] || { echo "missing $f"; exit 1; }
done

stage="dist/release/tailscale-nx-$version"
rm -rf "$stage"
mkdir -p "$stage/atmosphere/contents" "$stage/switch/.overlays" "$stage/config/tailscale-nx"
cp -R "$contents" "$stage/atmosphere/contents/"
cp switch/overlay/tailscale-nx.ovl "$stage/switch/.overlays/"
cp switch/sysmodule/res/config.ini.example "$stage/config/tailscale-nx/"

zip="dist/tailscale-nx-$version.zip"
rm -f "$zip"
(cd "$stage" && zip -qrX "$root/$zip" atmosphere switch config -x '.*' -x '*/.DS_Store')
echo "built $zip"
unzip -l "$zip" | tail -n +4 | sed '$d' | sed '$d' | awk '{print "  " $4}'
