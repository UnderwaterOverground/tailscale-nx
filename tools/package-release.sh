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

# The overlay's version is a compiler flag, which make doesn't track: force a
# recompile so the on-screen version is right (checked below). Touching
# rather than deleting outputs: Docker on macOS can keep a stale view of
# files deleted on the host, and the link then fails.
touch switch/overlay/source/main.cpp
make sysmodule overlay >/dev/null
strings -n 4 switch/overlay/tailscale-nx.elf | grep -q "tailscale-nx $version" || { echo "overlay doesn't say $version"; exit 1; }
# The NACP holds the name, author and version Ultrahand shows.
nacp=switch/overlay/tailscale-nx.nacp
[[ $(wc -c < "$nacp") -eq 16384 ]] && strings -n 4 "$nacp" | grep -qx "$version" && strings -n 4 "$nacp" | grep -qx UnderwaterOverground ||
  { echo "$nacp is stale or malformed (delete it and rebuild)"; exit 1; }
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
