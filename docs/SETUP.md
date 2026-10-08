# Setting up tailscale-nx

tailscale-nx puts a modded Switch on your [Tailscale](https://tailscale.com)
tailnet. It runs in the background from boot. Homebrew such as Moonlight can
then reach your other devices by their `100.x` addresses or tailnet names,
from anywhere.

It affects **homebrew only** (apps launched from hbmenu, and home-screen
forwarders you list in `mitm_titles`). Games and Nintendo's own apps never
see the tailnet.

## What you need

- **Atmosphère**: tested with 1.12.0 on firmware 22.5.0. To set it up, follow
  the [NH Switch Guide](https://switch.hacks.guide/).
- **[Ultrahand Overlay](https://github.com/ppkantorski/Ultrahand-Overlay)**
  with nx-ovlloader. It is optional, but you need it for the status screen,
  the login QR code and the log-in toast.
- A **Tailscale account**. A self-hosted [headscale](https://headscale.net)
  works too.

## Install

Copy these to the SD card, merging folders:

| Path | What |
|---|---|
| `atmosphere/contents/4200000000005453/` | The sysmodule. `flags/boot2.flag` makes it start at boot. |
| `switch/.overlays/tailscale-nx.ovl` | The overlay: status, a pause switch, stop and start, and the login QR code |
| `config/tailscale-nx/config.ini.example` | Settings template (optional; see below) |

Then restart the console.

## Join your tailnet

Pick one of two ways.

### A. Log in with a link (no setup)

1. Within a minute of booting, Ultrahand shows a **"Tailscale: log in needed"**
   toast. It contains the link and the button combo for the overlay.
2. Open the overlay. The default is **L + D-pad Down + R3**; the toast shows
   yours. Choose **Tailscale**.
3. Scan the QR code with your phone, log in to Tailscale and approve the
   Switch.
4. The overlay changes to **Connected** and shows the Switch's `100.x`
   address.

The link is also saved to `config/tailscale-nx/login.txt` on the SD card, in
case you don't use Ultrahand.

### B. Use an auth key (nothing to do on the console)

1. Go to [Settings → Keys](https://login.tailscale.com/admin/settings/keys) in
   the Tailscale admin console and choose **Generate auth key**.
2. Choose its settings:
   - **Reusable: on.** If the Switch ever needs to log in again, it can do so
     on its own, as long as the auth key itself hasn't expired (see below).
   - **Ephemeral: off.** Tailscale deletes ephemeral devices soon after they
     go offline, and a Switch goes offline every time it sleeps.
   - **Expiration:** how long the key can add devices, up to 90 days. It
     doesn't limit the Switch once the Switch is added.
   - **Tags:** optional. Tagged devices have key expiry turned off by
     default, but you need a tag your account is allowed to use.
3. Copy `config/tailscale-nx/config.ini.example` to `config.ini` in the same
   folder, and set `auth_key=tskey-auth-…`.
4. Restart the console.

Treat `config.ini` like a password while it contains the key. Anyone with the
key can add devices to your tailnet. Once the Switch has joined, you can
delete the line.

## Turn off key expiry

By default, Tailscale makes every device log in again after **180 days**
(this is called key expiry). Until it does, the device is cut off. A Switch is
easy to forget about, so turn expiry off for it:

1. Open the [Machines](https://login.tailscale.com/admin/machines) page and
   find the Switch (default name `nintendo-switch`).
2. Open its **⋯** menu and choose **Disable key expiry**.

If the key does expire, tailscale-nx handles it the way Tailscale's own
clients do. It makes a new key and registers it in place of the old one:

- **With a reusable auth key in `config.ini`** that is still valid, it
  reconnects on its own.
- **Otherwise**, you get the same log-in toast and QR code as in way A.
  After you approve, the Switch keeps its name and `100.x` address.

Until either happens, the Switch can't reach the tailnet.

## Using it

- **Moonlight:** add your PC by its tailnet name (e.g. `gaming-pc`) or its
  `100.x` address. At home, Moonlight may also find the PC on the local
  network and use that, which is fine. Away from home, it uses the tailnet.
- **MagicDNS:** tailnet names are written into the hosts file Atmosphère is
  using (`atmosphere/hosts/emummc.txt`, `sysmmc.txt` or `default.txt`). They
  update when your tailnet changes.
  - Atmosphère's Nintendo blocking is left alone, and names containing
    "nintendo" are never added.
  - If there's no hosts file, MagicDNS stays off. tailscale-nx never creates
    one.
- **Connected notice:** after each boot, a 5-second toast shows
  "Connected. IP: 100.x.y.z" the first time the Switch connects. It doesn't
  appear again on wake or reconnect. Turn it off with **Notice when
  connected** in the overlay.
- **Taildrop:** send files to the Switch from your other devices (see
  [below](#taildrop)).
- **Pause:** use the **Tailscale** switch in the overlay. While paused,
  tailnet connections fail at once and everything else works normally.
- **Stop and start:** **Stop tailscale-nx** in the overlay ends the
  sysmodule and frees its memory, until the next boot or until you press
  **Start tailscale-nx**. Its boot setting doesn't change.
  - Close homebrew apps first. Stop is refused while one has sockets through
    tailscale-nx, because closing them would break the app. It's also
    refused for a moment around sleep and wake.
  - With `mitm=homebrew,sys-ftpd`, stopping restarts sys-ftpd, which drops
    any FTP connection.
  - Start works whether or not the boot setting is on, but not while
    `config/tailscale-nx/disabled` exists.
- **Turn it off completely:** in the **Sysmodules** overlay
  (ovl-sysmodules), turn off tailscale-nx's boot setting, then use **Stop**
  or restart. The Sysmodules overlay can't stop it itself: Atmosphère would
  freeze if its socket hook disappeared without being removed first.

## Taildrop

Send files to the Switch with [Taildrop](https://tailscale.com/kb/1106/taildrop),
like to any of your devices: **Send with Tailscale** in the share menu
(Windows, macOS, iOS, Android), or `tailscale file cp photo.jpg nintendo-switch:`.

- Files land in the **`Taildrop`** folder at the root of the SD card, and a
  toast says so (with Ultrahand installed).
- An existing file is never replaced: a second `photo.jpg` is saved as
  `photo (1).jpg`.
- A file is refused if it wouldn't leave 0.5% of the SD card free. The
  sending device shows why.
- While a file arrives it's called `<name>.partial`. If the transfer is
  interrupted, that file is deleted.
- **Files of 4 GB or more** on a FAT32 card are saved the way the Switch
  stores large games: as a folder of parts that the Switch and homebrew read
  as one file. On a computer it shows up as a folder. (A sender that doesn't
  announce the size, such as `tailscale file cp -` from a pipe, stops at
  4 GB on FAT32.)
- **Only your own devices can send.** That's the same rule as Tailscale's own
  apps. It doesn't work if the Switch was added with a **tagged** auth key,
  because a tagged device doesn't belong to you. Sharing between users of a
  tailnet isn't supported.
- Taildrop has to be enabled for your tailnet. It is by default, on
  Tailscale and on headscale.
- Turn it off with `taildrop=off` in `config.ini`.

## Subnet routes

If a device in your tailnet is a
[subnet router](https://tailscale.com/kb/1019/subnets), homebrew can reach
the networks it shares, e.g. a PC at home at `192.168.1.20` that doesn't run
Tailscale. This is on by default (`accept_routes=off` turns it off).

- When the Switch is itself on a network that a route covers (at home, for
  example), it reaches that network directly instead.
- Exit nodes aren't supported: internet traffic never goes through
  Tailscale.

## Access rules

tailscale-nx enforces your tailnet's
[access rules](https://tailscale.com/kb/1018/acls) (ACLs) for connections
coming in to the Switch, as every Tailscale device does. Something listening
on the Switch, such as an FTP server, is reachable only from devices your
rules allow. Connections the Switch makes are checked by the device they
reach.

## Settings (`config/tailscale-nx/config.ini`)

All settings are optional. They take effect after a restart.

| Key | Default | What |
|---|---|---|
| `auth_key` | none | Auth key for joining without a link (see above) |
| `hostname` | `nintendo-switch` | Device name in your tailnet |
| `control_url` | `https://controlplane.tailscale.com` | Your headscale URL, if you use headscale |
| `magicdns` | `on` | `off` stops writing tailnet names to the hosts file |
| `connect_notice` | `on` | `off` turns off the "Connected" toast at boot (as does the overlay switch) |
| `taildrop` | `on` | `off` stops receiving files with [Taildrop](#taildrop) |
| `accept_routes` | `on` | `off` ignores your tailnet's [subnet routes](#subnet-routes) |
| `mitm` | `homebrew` | Which programs can reach the tailnet: `homebrew`, `off`, or `homebrew,sys-ftpd` (see below) |
| `mitm_titles` | none | Title IDs of home-screen forwarders that can reach the tailnet too, up to 16 (see below) |
| `overlay_budget_kb` | `320` | Memory for tailnet sockets, shared by all apps (128–512). Raise it only if apps report "no buffer space". |
| `ca_cert` | none | Extra CA certificate (DER) for a self-signed headscale |
| `log_udp` | none | Send the log to `ip:port` over UDP, e.g. to `nc -ul 5514` on a computer |

### Home-screen forwarders

Homebrew started from a home-screen forwarder runs as its own title, not
through hbmenu, so it can't reach the tailnet by default. To let it, add the
forwarder's title ID (16 hex digits) to `mitm_titles`, separating several
with commas or spaces:

```ini
mitm_titles=0500000000001234, 05ABCDEF00000000
```

The title ID is the one the forwarder was made with. The tool that made it
shows it, and title managers such as DBI or Goldleaf list installed titles
with their IDs. List only forwarders, and restart after changing it. The log
shows which IDs were accepted. `mitm=off` turns this off too.

### FTP over the tailnet (sys-ftpd)

With `mitm=homebrew,sys-ftpd`, the sys-ftpd sysmodule is also reachable on
the Switch's tailnet address or name, e.g. `ftp://nintendo-switch:5000`.
This costs about 70 KB more memory, and tailscale-nx restarts sys-ftpd once
at boot to take it over. FTP on the local network keeps working as before.

sys-ftpd itself has two limits, with or without tailscale-nx:
- **Speed:** about 11–14 Mbit/s on the local network and 5–7 Mbit/s over
  the tailnet.
- **Back-to-back transfers:** after two large transfers in a row, it refuses
  connections for about 10 seconds while its sockets close.

For big transfers, the ftpd homebrew app is much faster. It reaches the
tailnet with the default `mitm=homebrew`.

Serving sys-ftpd also uses extra system sessions, which every sysmodule
shares. On consoles running many sysmodules, other homebrew (such as
Moonlight) may be unable to connect while it's on. If that happens, go back
to `mitm=homebrew`.

## Memory

tailscale-nx uses about **2.6 MB** of the memory the system sets aside for
sysmodules: 0.9 MB of code and 1.7 MB of data, including a fixed 1 MB heap.
The heap is typically 15–30% full. Busy tailnet sockets use
more of it, up to the `overlay_budget_kb` limit.

## Troubleshooting

- **The overlay says the sysmodule isn't running.**
  - Check that `atmosphere/contents/4200000000005453/flags/boot2.flag`
    exists.
  - If `config/tailscale-nx/crashed` exists, tailscale-nx turned itself off.
    It does this after 3 boots in a row that ended within 3 minutes, or 2
    sleeps the console never woke from. The file says which. **Turn back on**
    in the overlay deletes it and starts tailscale-nx again.
  - If `config/tailscale-nx/disabled` exists, delete it.
- **What happened?**
  - The log is in `config/tailscale-nx/sysmodule.log`, and the previous
    boot's log is in `sysmodule.log.1`.
  - To watch it live, set `log_udp` to a computer's address.
- **An app reports "no buffer space" (errno 105).**
  - All apps share the tailnet socket memory. Raise `overlay_budget_kb`.
- **Moonlight finds the PC at home but not away.**
  - Check that Moonlight's saved host includes the tailnet name or `100.x`
    address, and that the overlay shows **Connected**.

Still stuck? Ask on [Discord](https://discord.gg/GjUuBEqRYb) or
[open an issue](https://github.com/UnderwaterOverground/tailscale-nx/issues),
with your `sysmodule.log`.
