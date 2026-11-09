# gAudit

**A security check-up for your GNOME desktop, written for people who are not security experts.**

gAudit looks at the security state of a Linux computer and explains in plain language what is fine and what needs attention. It does not change anything itself. It checks that the right things are in place and are actually being used. When something is missing, it shows the exact command to fix it, for you to copy or run.

> [!WARNING]
> gAudit is in early development. The framework and the first status checks work, but the privileged checks, the plugin system and the rule engine are still stubs. Do not rely on it to judge the security of a machine yet.

## Overview

Most security tools for Linux are written for administrators. gAudit is for the person who has heard the terms "firewall" and "updates", wants to do the right thing, and needs a clear answer: *is this computer looked after?*

- **Read-only.** gAudit inspects and reports. Updating, scanning and configuring are left to the tools that do the job, such as apt and ClamAV.
- **Honest results.** A green result means "no signs of problems found", never "this computer is safe". When a check cannot tell, it says *unknown* instead of guessing.
- **Defensive by design.** gAudit assumes a compromised machine may try to give misleading answers. It reads system files directly instead of parsing other tools' output, runs each check with the least privileges it needs, and treats everything from child processes as untrusted.

## What it checks today

The Home page gives a quick status that never asks for a password:

| Check | What it looks at |
|---|---|
| Antivirus | Whether a known antivirus program is installed |
| Firewall | Whether a known firewall is installed |
| Automatic updates | Whether security updates are installed automatically |
| Checking for updates | When the package lists were last refreshed |
| Pending updates | Updates waiting to be installed, following apt's own candidate selection (pinning, backports, phased updates) |
| Packages without a source | Installed packages that no software source offers any more, so they never get security fixes |

Deeper checks, such as whether the firewall is actually active or whether virus scans run regularly, will come as plugins with their own options and reports.

> [!NOTE]
> The first platform is Ubuntu. Distro-specific code sits behind a small backend interface, so other distributions can be added later.

## Getting started

### Requirements

- Ubuntu with GNOME (the current development target)
- CMake 3.25 or newer, a C17/C++20 compiler and `pkg-config`
- GTK 4 and libadwaita 1.4 or newer
- gettext

```sh
sudo apt install build-essential cmake pkg-config libgtk-4-dev libadwaita-1-dev gettext desktop-file-utils
```

### Build and run

```sh
cmake --preset dev
cmake --build --preset dev
build/dev/src/gui/gaudit
```

The `dev` preset runs everything from the build tree, translations included. Use `release` for a build with the installed paths.

> [!TIP]
> On a machine with little memory, limit parallel jobs with `cmake --build --preset dev -j 4`, or define your own presets in a `CMakeUserPresets.json` (ignored by git).

### Run the tests

```sh
ctest --preset dev
```

The tests are small, hand-written programs that use fixtures in `tests/data/`. They cover the model, the status probes, the apt configuration reader and the dpkg/apt package scan.

Developer builds also include `build/dev/tools/gaudit-probe-dump`. It runs the status checks on your machine and prints the raw results, so you can compare them with apt.

## How it is built

```text
GUI (user)  ──>  orchestrator (user)
                   ├─ privileged helper (pkexec, minimal)
                   │     └─ check processes, privileges dropped per check
                   └─ rule engine (Guile, sandboxed, no privileges)
```

| Directory | Contents |
|---|---|
| `src/gui/` | GTK4/libadwaita interface in C |
| `src/model/` | Model in C++ behind a plain C API |
| `src/probe/` | Unprivileged status probes for Home |
| `src/backend/` | Distro backend interface and the Ubuntu implementation |
| `src/helper/`, `src/orchestrator/`, `src/engine/` | Privileged helper, orchestrator and rule engine (stubs) |
| `data/` | Desktop file and polkit policy |
| `po/` | Translations |
| `tests/` | Tests and fixtures |

Design decisions, the threat model and the plugin and trust model are described in [AGENTS.md](AGENTS.md).

## Translations

gAudit uses gettext and ships with a Norwegian Bokmål translation. After changing user-facing text, run:

```sh
cmake --build --preset dev --target update-po
```

Then translate the new strings in `po/<language>.po`. Translations affect security too: a wrong word can make a warning read as harmless. New languages therefore need a native speaker to review them before they ship.

## Acknowledgements

Created with assistance from AI tools (Claude Opus) across all parts of this work.

This project was developed independently, with no external financial or institutional support other than the AI tools mentioned.
