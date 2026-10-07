#!/usr/bin/env python3
"""Attributes .text/.rodata/.data/.bss bytes in a GNU ld map file to the
archive (or object) they came from, to see what the sysmodule is made of.

  tools/map-sizes.py switch/sysmodule/tailscale-nx.map [--objects]
"""
import re, sys, collections

path = sys.argv[1]
by_object = "--objects" in sys.argv
sizes = collections.defaultdict(lambda: collections.Counter())
section_re = re.compile(r'^ (\.(text|rodata|data|bss|data\.rel\.ro|tbss|tdata)[^\s]*)\s*(0x[0-9a-f]+)?\s*(0x[0-9a-f]+)?\s*(.*)$')
pending = None
in_discard = False
started = False  # input sections listed before the memory map were discarded by --gc-sections
for line in open(path, errors="replace"):
    if not started:
        started = line.startswith("Linker script and memory map")
        continue
    if line.startswith("/DISCARD/"):
        in_discard = True
    elif line.startswith("OUTPUT(") or (line and not line[0].isspace() and line.startswith(".")):
        in_discard = False
    if in_discard:
        continue
    if pending:
        m = re.match(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.*)$', line)
        pending_kind, = pending
        pending = None
        if m:
            size, src = int(m.group(2), 16), m.group(3).strip()
        else:
            continue
    else:
        m = section_re.match(line)
        if not m:
            continue
        name, kind = m.group(1), m.group(2)
        if not m.group(4):
            pending = (kind,)
            continue
        size, src = int(m.group(4), 16), m.group(5).strip()
        pending_kind = kind
    if size == 0 or not src:
        continue
    kind = pending_kind
    kind = {"data.rel.ro": "rodata", "tdata": "data", "tbss": "bss"}.get(kind, kind)
    if by_object:
        key = src
    else:
        a = re.match(r'(.*/)?([^/(]+)\((.*)\)$', src)
        key = a.group(2) if a else src.split("/")[-1]
        # Rust staticlib members: crate name from the codegen unit name.
        if a and a.group(2).startswith("libtsnx_ffi"):
            member = a.group(3)
            key = "rust:" + re.sub(r'(-[0-9a-f]{16})?\..*$', '', member).split("-")[0]
    sizes[key][kind] += size

rows = sorted(sizes.items(), key=lambda kv: -(kv[1]["text"] + kv[1]["rodata"] + kv[1]["data"]))
tot = collections.Counter()
print(f"{'text':>9} {'rodata':>9} {'data':>8} {'bss':>9}  source")
for k, c in rows:
    tot.update(c)
    if c["text"] + c["rodata"] + c["data"] + c["bss"] >= 4096:
        print(f"{c['text']:>9} {c['rodata']:>9} {c['data']:>8} {c['bss']:>9}  {k}")
print(f"{tot['text']:>9} {tot['rodata']:>9} {tot['data']:>8} {tot['bss']:>9}  TOTAL")
