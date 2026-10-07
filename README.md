# tailscale-nx

[![Release](https://img.shields.io/github/v/release/UnderwaterOverground/tailscale-nx)](https://github.com/UnderwaterOverground/tailscale-nx/releases/latest)
[![License](https://img.shields.io/badge/license-GPL--2.0%20%2F%20BSD--3-blue)](#license)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?logo=discord&logoColor=white)](https://discord.gg/GjUuBEqRYb)

**Tailscale for the Nintendo Switch.** tailscale-nx runs in the background
on a Switch with Atmosphère and puts it on your
[Tailscale](https://tailscale.com) network (your *tailnet*). Homebrew such as
[Moonlight](https://github.com/XITRIX/Moonlight-Switch) can then reach your
PC, NAS and other devices by their tailnet address or name, from anywhere,
without opening ports on your router.

> tailscale-nx is an unofficial, community project. It is not affiliated
> with or endorsed by Tailscale Inc. or Nintendo.

## Features

- **Starts at boot** and stays connected in the background, through sleep
  and wake.
- **Homebrew reaches your tailnet:** apps launched from hbmenu can connect
  to `100.x.y.z` addresses and tailnet names (MagicDNS). Nothing to set up
  per app.
- **Direct connections** between devices where possible, with Tailscale's
  relays (DERP) as a fallback, just like the official clients.
- **Overlay** (Ultrahand): status, the Switch's tailnet IP, a pause switch,
  and a QR code for logging in.
- **Easy login:** scan a QR code, or put an auth key in a config file. Key
  expiry is handled.
- **Respects your tailnet's access rules (ACLs)** for incoming connections.
- **Optional:** reach the Switch's [sys-ftpd](https://github.com/cathery/sys-ftpd)
  over the tailnet.
- **Small:** about 2.6 MB of memory.

## Requirements

- A Switch running [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere)
  custom firmware. Tested with Atmosphère 1.12.0 on firmware 22.5.0
  (Mariko).
- [Ultrahand Overlay](https://github.com/ppkantorski/Ultrahand-Overlay):
  optional, but needed for the overlay and the on-screen login prompt.
- A [Tailscale](https://tailscale.com) account, or a
  [headscale](https://headscale.net) server.

## Install

1. Download `tailscale-nx-<version>.zip` from the
   [latest release](https://github.com/UnderwaterOverground/tailscale-nx/releases/latest).
2. Extract it to the root of your SD card, merging folders.
3. Restart the console.
4. Within a minute, a **"Tailscale: log in needed"** notification appears.
   Open the overlay (default **L + D-pad Down + R3**), choose
   **Tailscale**, scan the QR code with your phone, and approve the Switch.

That's it: the overlay shows **Connected** and the Switch's `100.x`
address. **Turn off key expiry** for the Switch in the Tailscale admin
console, so it never has to log in again.

The [setup guide](docs/SETUP.md) covers auth keys, key expiry, all
settings, sys-ftpd and troubleshooting.

## Using it with Moonlight

Add your PC in Moonlight by its tailnet name (e.g. `gaming-pc`) or its
`100.x` address. At home, Moonlight may find the PC on your local network
and use that instead, which is fine. Away from home, it uses the tailnet.

## Known limitations

- **Homebrew only**, and only apps launched from hbmenu. Games, Nintendo's
  apps and homebrew started from a home-screen forwarder don't use the
  tailnet.
- **No subnet routes or exit nodes:** only tailnet addresses
  (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) go through Tailscale.
- **No Taildrop or Tailscale SSH.**
- The Switch connects to the internet over **IPv4 only** (tailnet IPv6
  addresses work).
- tailscale-nx can't be stopped while it runs. Turning it off (in the
  Sysmodules overlay) takes a restart.
- Tested on one Mariko Switch. Reports from other models and firmware
  versions are welcome.

## Questions

**Does it affect games or online play?** No. It only handles traffic from
homebrew to tailnet addresses. It doesn't change how games or Nintendo
services connect. MagicDNS leaves Atmosphère's DNS blocking of Nintendo
servers in place.

**Is my traffic private?** Like the official Tailscale clients, tailnet
traffic is encrypted end to end with WireGuard. Tailscale's servers
coordinate keys and relay encrypted packets when a direct connection isn't
possible.

**Something's wrong.** See [troubleshooting](docs/SETUP.md#troubleshooting).
For help, ask on [Discord](https://discord.gg/GjUuBEqRYb) or
[open an issue](https://github.com/UnderwaterOverground/tailscale-nx/issues).
Please include the log, `config/tailscale-nx/sysmodule.log` on the SD card.

## Building

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Everything builds in Docker,
and most of it can be tested on a computer without a Switch.

## Credits

tailscale-nx builds on:
- **[tailscale-rs](https://github.com/tailscale/tailscale-rs):** Tailscale's
  Rust components (WireGuard, keys, disco).
- **Libraries:**
  - [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere)'s libstratosphere
  - [libnx](https://github.com/switchbrew/libnx)
  - [libtesla](https://github.com/WerWolv/libtesla)
  - [smoltcp](https://github.com/smoltcp-rs/smoltcp)
  - [rustls](https://github.com/rustls/rustls)
  - [RustCrypto](https://github.com/RustCrypto)
  - [QR Code generator](https://www.nayuki.io/page/qr-code-generator-library)
- **Ideas:** from [sys-GRID0](https://github.com/redluigi323/sys-GRID0),
  [ryu_ldn_nx](https://github.com/Ethiquema/ryu_ldn_nx) and
  [wireguard-nx](https://github.com/chrisbraucker/wireguard-nx).

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for licences.

## License

- **The project** is licensed under the GNU General Public License v2.0 or
  later ([LICENSE](LICENSE)). This covers the sysmodule, the overlay and the
  socket layer, which link GPL-2.0 libraries.
- **The Rust engine** in `crates/` is licensed under the BSD 3-Clause
  License ([crates/LICENSE](crates/LICENSE)), like the tailscale-rs code it
  builds on.

## Found it useful?

If tailscale-nx helped you, a ⭐ on the repo is always appreciated. It's how
we know it's helping someone.
