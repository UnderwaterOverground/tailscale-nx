#!/bin/sh
# Keeps the sysmodule's memory at exactly 2.5 MB (2560 KB): sizes its heap
# (switch/sysmodule/source/heap_size.h) to fill what the code leaves. The
# kernel charges a sysmodule its loaded image (code, data and the static
# heap, page by page) plus its main thread's stack, once, at launch.
#
# Runs where devkitA64 is (the build image). Exit 0: exactly on target.
# Exit 3: heap_size.h was rewritten; rebuild. Other: an error.
set -eu
cd "$(dirname "$0")/.."
target=$((0x280000))
min_heap=$((768 * 1024))  # engine (~300 KB) + overlay_budget_kb up to 384 + slack
elf=switch/sysmodule/tailscale-nx.elf
header=switch/sysmodule/source/heap_size.h
readelf=/opt/devkitpro/devkitA64/bin/aarch64-none-elf-readelf

stack=$(($(sed -n 's/.*"main_thread_stack_size": *"\(0x[0-9A-Fa-f]*\)".*/\1/p' switch/sysmodule/res/app.json)))
image=0
for memsz in $("$readelf" -lW "$elf" | awk '$1 == "LOAD" { print $6 }'); do
  image=$((image + (memsz + 0xfff) / 0x1000 * 0x1000))
done
heap=$(($(sed -n 's/^#define TSNX_HEAP_SIZE \(0x[0-9A-Fa-f]*\).*/\1/p' "$header")))
total=$((image + stack))
if [ "$total" -eq "$target" ]; then
  echo "footprint: $((total / 1024)) KB (heap $((heap / 1024)) KB)"
  exit 0
fi
new=$((heap + target - total))
if [ $((new % 4096)) -ne 0 ] || [ "$new" -lt "$min_heap" ]; then
  echo "footprint: $((total / 1024)) KB; a $((target / 1024)) KB total would leave a $((new / 1024)) KB heap (minimum $((min_heap / 1024)) KB)" >&2
  exit 1
fi
cat > "$header" <<HDR
// The sysmodule's heap size, written by tools/footprint.sh (make sysmodule):
// it fills the sysmodule's memory up to exactly 2.5 MB (2560 KB) with the
// code as built. Commit it with the code change that moved it.
#define TSNX_HEAP_SIZE $(printf '0x%X' "$new")
HDR
echo "footprint: was $((total / 1024)) KB; heap $((heap / 1024)) -> $((new / 1024)) KB, rebuilding"
exit 3
