# Developing tailscale-nx

How the code is laid out, how to build and test it (mostly on a Mac or Linux
machine, without a console), and what we learned along the way.

## Layout

| Path | What |
|---|---|
| `crates/tsnx-core` | Sans-IO engine, `no_std + alloc`. It contains: <ul><li>ts2021 control: Noise IK, HTTP/2 + HPACK, register/map poll</li><li>DERP client</li><li>WireGuard via vendored `ts_tunnel`</li><li>smoltcp netstack with a socket API</li><li>a pure-Rust rustls provider</li></ul> It never touches sockets, clocks or OS RNGs; drivers inject them. |
| `crates/tsnx-ffi` | C ABI (`include/tsnx.h`), built as a staticlib for the Switch and for host C tests |
| `crates/tsnx-host` | Rust host driver with diagnostics: `selftest`, `tls-probe`, `control-probe`, `up` |
| `native/driver` | Portable POSIX C driver loop plus shared app logic (key state, echo test). The same code runs on macOS and libnx. |
| `native/host` | `tsnx-c`, a host CLI over the C driver, to test the Switch code paths on the Mac |
| `native/runtime` | C++ runtime: runs the engine on its own thread for multi-threaded callers |
| `native/vsock` | Socket virtualization. It decides per socket between the real stack and the tailnet, splits poll/select, and handles blocking semantics. The MITM is built on it. |
| `native/interpose` | `libtsnx_interpose`: runs unmodified programs through `native/vsock` (DYLD on macOS, LD_PRELOAD on Linux), plus `vsock-test` |
| `switch/sysmodule` | The boot2 sysmodule (libstratosphere): engine, `bsd:u` MITM (plus `bsd:s` for sys-ftpd), MagicDNS hosts file, the `tsnx:ctl` status service, sleep handling and the crash guard |
| `switch/overlay` | Tesla/Ultrahand overlay: status, pause switch, login QR code |
| `switch/app` | `tsnx-app.nro`: the engine in a homebrew app, with status, an echo self-test and a crypto benchmark (developer tool) |
| `third_party/tailscale-rs` | Vendored, `no_std`-ported crates from tailscale-rs (BSD-3). See `VENDORED.md`. |
| `e2e/` | Local tailnet: headscale (control, DERP, STUN) plus a stock `tailscaled` peer with TCP/UDP echo (port 7), HTTP (8080) and iperf3 (5201). `run-tests.sh` is the automated suite. |

## Build and test

Requirements: Rust (stable for the host, nightly is pulled into the Docker image) and Docker.

```sh
make host-test        # unit tests: crypto vectors, HPACK RFC vectors, HTTP/2, Noise, DERP, netstack
make docker-image     # once: devkitA64 + libnx + Rust nightly (native arm64)
make sysmodule        # switch/sysmodule/dist: atmosphere/contents/4200000000005453 (exefs.nsp, boot2 flag)
make overlay          # switch/overlay/tailscale-nx.ovl
tools/stage-sd.sh     # dist/sd: a ready-to-copy SD tree (Atmosphère, hekate, sysmodule, overlay)
make nro              # switch/app/tsnx-app.nro
make host-c           # target/tsnx-c (C driver + FFI on the Mac)
make interpose        # target/libtsnx_interpose.dylib + target/vsock-test
make e2e              # local tailnet + the full end-to-end suite (Docker)
```

`make e2e` checks the following against a stock `tailscaled`:
- TCP/UDP echo, upgrading to a direct path
- the same with direct UDP blocked (DERP only)
- inbound disco ping and ICMP
- the socket virtualization suite and unmodified curl through the shim
- a 50 Mbit/s UDP stream (Moonlight-like) and a TCP bulk upload through the shim
- replacing an expired node key, both while running (auth key) and at startup (login URL)

Typical results on a Mac's Docker VM: 50 Mbit/s UDP at 0% loss; about 800 Mbit/s TCP up and 680 Mbit/s down.

### Local tailnet (no console needed)

```sh
e2e/setup.sh          # headscale + peer1 (100.64.0.1) with echo services; prints the auth key
# Rust driver:
TSNX_EXTRA_ROOT=e2e/state/certs/ca.der \
TSNX_CONNECT_MAP=headscale:443=127.0.0.1:8443,172.30.0.10:443=127.0.0.1:8443 \
  cargo run -p tsnx-host -- up --control https://headscale --authkey "$(cat e2e/state/authkey)" \
    --state e2e/state/host/mac.state --echo-test 100.64.0.1
# C driver (what the Switch runs):
TSNX_CONNECT_MAP=headscale:443=127.0.0.1:8443,172.30.0.10:443=127.0.0.1:8443 \
  target/tsnx-c --control https://headscale --authkey "$(cat e2e/state/authkey)" \
    --extra-root e2e/state/certs/ca.der --state e2e/state/host/c.state --echo-test 100.64.0.1
# Inbound from the stock client:
docker compose -f e2e/docker-compose.yml exec peer tailscale ping --icmp <tsnx ip>
e2e/down.sh           # tear down and delete state
```

`TSNX_CONNECT_MAP` lets the Mac reach the container hostnames through the
published port. It is for development only.

### Running unmodified programs over the tailnet (the MITM's code paths)

```sh
TSNX_CONTROL_URL=https://headscale TSNX_EXTRA_ROOT=e2e/state/certs/ca.der \
TSNX_CONNECT_MAP=headscale:443=127.0.0.1:8443,172.30.0.10:443=127.0.0.1:8443 \
TSNX_STATE=e2e/state/host/interpose.state TSNX_AUTHKEY="$(cat e2e/state/authkey)" TSNX_WAIT_READY=1 \
DYLD_INSERT_LIBRARIES=target/libtsnx_interpose.dylib target/vsock-test 100.64.0.1 1.1.1.1:443
```

`TSNX_TRACE=1` logs every intercepted socket call. `TSNX_LOG_LEVEL=1..5` shows
the core's logs. SIP-protected binaries (`/usr/bin/curl`) ignore
`DYLD_INSERT_LIBRARIES`; use the Linux container for those (`e2e/run-tests.sh`
shows how).

### On the console

Sysmodule loop (a console with sys-ftpd, reachable at `<switch ip>`):

1. `make sysmodule` (and `make overlay`), then copy
   `switch/sysmodule/dist/atmosphere/contents/4200000000005453/exefs.nsp`
   (and `switch/overlay/tailscale-nx.ovl`) over FTP.
2. Reboot. tailscale-nx can't be restarted while running: its `bsd:u`
   MITM must outlive every client session.
3. Watch the log: set `log_udp=<your ip>:5514` in
   `config/tailscale-nx/config.ini` and run `nc -ul 5514`, or read
   `config/tailscale-nx/sysmodule.log(.1)`.

Crashes are logged with module-relative offsets (`CRASH desc ... pc +0x...`);
resolve them with `aarch64-none-elf-addr2line -e switch/sysmodule/tailscale-nx.elf`.

`switch/app` (`tsnx-app.nro`) runs the same engine as an ordinary homebrew
app with an echo self-test and a crypto benchmark (`make nxlink
NXLINK_HOST=<switch ip>` streams its output). Don't run it alongside the
sysmodule: they share node keys.

### A complete SD card tree

`tools/stage-sd.sh` stages `dist/sd/`: Atmosphère 1.12.0, hekate, the
sysmodule, the overlay and the test app. It's handy for setting up a test
console. Copy it with rsync, which merges folders. Finder's "Replace"
deletes what's already in a folder, such as other sysmodules or
`hekate_ipl.ini`:

```sh
rsync -rtv --exclude .DS_Store dist/sd/ /Volumes/<SD card>/
dot_clean -m /Volumes/<SD card>
```

## Releases

`make release` builds `dist/tailscale-nx-<version>.zip` (the files to
extract to the SD card root). The version comes from `Cargo.toml` and must
match `switch/overlay/Makefile` and `switch/sysmodule/res/app.json`.
Pushing a `v*` tag builds and publishes the same zip on GitHub
(`.github/workflows/publish.yml`).

## Notes and findings

- **Disco keys are persisted.** Go clients make a new disco key every run,
  and peers reset their WireGuard sessions when they see one. That races with
  the handshake a restarted node starts straight away, and costs about 15 s
  of dead traffic. Persisting the key, which is no more linkable than the
  persistent node key, avoids the race. Data arriving for an unknown session
  triggers an immediate re-handshake.
- **The engine adds WireGuard's "no response for 15 s, re-handshake" rule**,
  which `ts_tunnel` lacks.
- **DERP servers queue only 32 packets per client.** Bursts beyond that are
  dropped, as with any Tailscale client, and TCP recovers.
- **Consoles often have wrong clocks** (HATS-style DNS blocklists block Nintendo NTP; one test console
  was at 2053), which breaks TLS. The app prefers the network clock, and falls back to the control
  server's HTTP `Date` (bounded to [build date, build date + 3 years]) with an on-screen warning.
- **Home DERP is chosen by latency** (STUN to every region, re-checked every 5 minutes, with hysteresis).
- **Tailscale's STUN servers** only answer requests that carry
  `SOFTWARE=tailnode` and a FINGERPRINT.
