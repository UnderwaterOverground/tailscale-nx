# Contributing

Thanks for helping. Bug reports, logs and pull requests are all welcome.

## Reporting a problem

Open an [issue](https://github.com/UnderwaterOverground/tailscale-nx/issues)
or ask on [Discord](https://discord.gg/GjUuBEqRYb). Please include:

- `config/tailscale-nx/sysmodule.log` from the SD card (and
  `sysmodule.log.1` if the problem was before the last restart). It has no
  keys or passwords, but it does show your public IP and your tailnet's
  device names, so trim those if you like.
- Your firmware and Atmosphère versions, and which other sysmodules you run.
- What you were doing when it happened: streaming, waking from sleep,
  changing networks.

## Pull requests

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers building and testing.
Most of it runs on a computer, without a Switch: `make host-test` for the
unit tests, and `e2e/` for a local tailnet.

- Keep a pull request to one change, with a test where you can.
- The sysmodule shares a small pool of memory with every other sysmodule,
  so it must stay at 2.5 MB. `make sysmodule` checks this.
- Say how you tested it, especially on a console.

Every pull request is reviewed and tested here, on a console too if it
changes how tailscale-nx runs, before it's merged. Merged changes ship in
the next release, with thanks in its notes.
