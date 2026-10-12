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
- **Subnet routes:** reach devices on networks your tailnet shares through a
  subnet router, such as a PC at home that doesn't run Tailscale.
- **Direct connections** between devices where possible, with Tailscale's
  relays (DERP) as a fallback, just like the official clients.
- **Overlay** (Ultrahand): status, the Switch's tailnet IP, a pause switch,
  stop and start, and a QR code for logging in.
- **Update notice:** a notification at boot when a newer release is out
  (can be turned off).
- **Easy login:** scan a QR code, or put an auth key in a config file. Key
  expiry is handled.
- **Taildrop:** send files to the Switch from your phone or computer. They
  land in the SD card's `Taildrop` folder.
- **Respects your tailnet's access rules (ACLs)** for incoming connections.
- **Optional:** reach the Switch's [sys-ftpd](https://github.com/cathery/sys-ftpd)
  over the tailnet.
- **Small:** exactly 2.5 MB of memory, fixed when it starts.

## Before you start

You need:

- **A Switch with [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere)**
  custom firmware. If you're not sure what that is, follow the
  [NH Switch Guide](https://switch.hacks.guide/) first. Tested with
  Atmosphère 1.12.0 on firmware 22.5.0 (Mariko).
- **[Ultrahand Overlay](https://github.com/ppkantorski/Ultrahand-Overlay)**.
  To check you have it, press **L + D-pad Down + R3** (R3 is pressing the
  right stick in) on the home screen: a menu should appear over the screen.
  You can do without it (see the [setup guide](docs/SETUP.md)), but logging
  in is much easier with it.
- **A free [Tailscale](https://tailscale.com) account**, with Tailscale
  installed on the PC or other device you want the Switch to reach.
  A [headscale](https://headscale.net) server works too.

## Install

### 1. Download

Open the [latest release](https://github.com/UnderwaterOverground/tailscale-nx/releases/latest)
and, under **Assets**, download **`tailscale-nx-<version>.zip`** (not "Source
code"). Unzip it. Inside are three folders: **`atmosphere`**, **`config`**
and **`switch`**.

### 2. Copy it to the SD card

Turn the Switch off (hold the power button, then **Power Options → Turn
Off**), take out the SD card and put it in your computer.

The SD card already has `atmosphere` and `switch` folders. The new files go
*inside* them, next to what's already there. Nothing on the card gets
deleted.

- **Windows:** select the three folders and drag them onto the SD card
  itself (not into a folder on it). If Windows asks about files with the same
  name, choose **Replace the files in the destination**.
- **Mac:** don't drag the three folders onto the card: Finder would
  *replace* your whole `atmosphere` folder instead of adding to it. Copy
  these two items one at a time instead:

  | From the zip | Drag it into this folder on the SD card |
  |---|---|
  | `atmosphere/contents/4200000000005453` | `atmosphere/contents` |
  | `switch/.overlays/tailscale-nx.ovl` | `switch/.overlays` |

  Folders starting with a dot are hidden on a Mac: press
  **Cmd + Shift + .** in Finder to show them. If Finder asks whether to
  replace an older version, choose **Replace**.

**Check it:** the SD card should now have these two files. If there's a
folder called `tailscale-nx-…` on the card, the files are in the wrong place:
move its contents out to the top of the card.

```
atmosphere/contents/4200000000005453/exefs.nsp
switch/.overlays/tailscale-nx.ovl
```

Put the SD card back in the Switch and turn it on as you normally would.

### 3. Log in

1. Wait for a **"Tailscale: log in needed"** notification. It appears within
   a minute of the Switch connecting to Wi-Fi.
2. Press **L + D-pad Down + R3** to open Ultrahand and choose **Tailscale**.
3. Scan the QR code with your phone's camera, log in to Tailscale and
   approve the Switch.
4. The overlay changes to **Connected** and shows the Switch's address,
   starting `100.`. You're done.

### 4. Stop it logging out after 6 months

Tailscale makes devices log in again every 180 days. To stop that for the
Switch, open the [Machines](https://login.tailscale.com/admin/machines) page,
find **nintendo-switch**, open its **⋯** menu and choose **Disable key
expiry**.

### It didn't work

- **No notification after a few minutes:** check the two files above are in
  exactly those places, and that you restarted the Switch (not just put it to
  sleep and woke it).
- **There's no Tailscale in Ultrahand's menu:** `tailscale-nx.ovl` isn't in
  `switch/.overlays`.
- **Something else:** see [troubleshooting](docs/SETUP.md#troubleshooting).

### Updating

Download the new zip and copy it over the old files the same way. Your login
and settings are kept. Restart the Switch afterwards.

The [setup guide](docs/SETUP.md) covers logging in with an auth key instead,
all the settings, sys-ftpd and more.

## Using it with Moonlight

Add your PC in Moonlight by its tailnet name (e.g. `gaming-pc`) or its
`100.x` address. At home, Moonlight may find the PC on your local network
and use that instead, which is fine. Away from home, it uses the tailnet.

## Known limitations

- **Homebrew only**: apps launched from hbmenu or another homebrew launcher,
  and home-screen forwarders (those with title IDs starting `01` need
  listing in `mitm_titles`, see the
  [setup guide](docs/SETUP.md#home-screen-forwarders)). Games and Nintendo's
  apps don't use the tailnet.
- **No exit nodes:** only tailnet addresses and your tailnet's subnet routes
  go through Tailscale.
- **No Tailscale SSH**, and Taildrop only receives (the Switch can't send
  files).
- The Switch connects to the internet over **IPv4 only** (tailnet IPv6
  addresses work).
- To stop tailscale-nx while it runs, use **Stop** in its own overlay
  (close homebrew apps first). The Sysmodules overlay can't stop it: turning
  it off there takes a restart.
- Tested on one Mariko Switch. Reports from other models and firmware
  versions are welcome.

## Questions

**Does it affect games or online play?** No. It only handles traffic from
homebrew to tailnet addresses. It doesn't change how games or Nintendo
services connect. MagicDNS leaves Atmosphère's DNS blocking of Nintendo
servers in place.

**The console crashes (orange screen) when I wake it during a Moonlight
stream.** That's a Moonlight-Switch bug
([#306](https://github.com/XITRIX/Moonlight-Switch/issues/306)), and it
happens with tailscale-nx turned off too. Until it's fixed, end the stream
before putting the console to sleep.

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
