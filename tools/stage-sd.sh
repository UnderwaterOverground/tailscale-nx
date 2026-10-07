#!/usr/bin/env bash
# Stages a ready-to-copy SD card tree in dist/sd: Atmosphère + fusee, hekate,
# the tailscale-nx sysmodule (starts at boot) and overlay, the test app and an
# example config. Copy dist/sd/* onto the SD
# card root, merging folders. Existing configs (hekate_ipl.ini, atmosphere
# config, tailscale-nx config) are not in this tree and are left untouched,
# except config.ini.example which never overwrites a real config.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dl="$root/dist/downloads"
sd="$root/dist/sd"
ams_zip="atmosphere-1.12.0-master-28d6a2e11+hbl-2.4.5+hbmenu-3.6.1.zip"
hekate_zip="hekate_ctcaer_6.5.4_Nyx_1.9.4.zip"

mkdir -p "$dl"
fetch() { [[ -f "$dl/$2" ]] || curl -sSfL -o "$dl/$2" "$1"; }
fetch "https://github.com/Atmosphere-NX/Atmosphere/releases/download/1.12.0/$ams_zip" "$ams_zip"
fetch "https://github.com/Atmosphere-NX/Atmosphere/releases/download/1.12.0/fusee.bin" fusee.bin
fetch "https://github.com/CTCaer/hekate/releases/download/v6.5.4/$hekate_zip" "$hekate_zip"

make -C "$root" nro sysmodule overlay >/dev/null
[[ -f "$root/switch/app/tsnx-app.nro" && -f "$root/switch/overlay/tailscale-nx.ovl" ]]
[[ -f "$root/switch/sysmodule/dist/atmosphere/contents/4200000000005453/flags/boot2.flag" ]]

[[ "$sd" == "$root/dist/sd" ]] && rm -rf "$sd"
mkdir -p "$sd/bootloader/payloads" "$sd/switch/tailscale-nx" "$sd/switch/.overlays" "$sd/config/tailscale-nx"
unzip -q "$dl/$ams_zip" -d "$sd"
unzip -q "$dl/$hekate_zip" -d "$sd"
cp "$dl/fusee.bin" "$sd/bootloader/payloads/fusee.bin"
cp "$root/switch/app/tsnx-app.nro" "$sd/switch/tailscale-nx/tailscale-nx.nro"
mkdir -p "$sd/atmosphere/contents"
cp -R "$root/switch/sysmodule/dist/atmosphere/contents/4200000000005453" "$sd/atmosphere/contents/"
cp "$root/switch/overlay/tailscale-nx.ovl" "$sd/switch/.overlays/tailscale-nx.ovl"
cp "$root/switch/sysmodule/res/config.ini.example" "$sd/config/tailscale-nx/config.ini.example"
# Payloads for RCM injection / modchips, outside the SD tree.
cp "$sd/hekate_ctcaer_6.5.4.bin" "$root/dist/payload-hekate.bin"
cp "$dl/fusee.bin" "$root/dist/payload-fusee.bin"
echo "staged $sd"
cp "$root/docs/SETUP.md" "$root/dist/SETUP.md"
