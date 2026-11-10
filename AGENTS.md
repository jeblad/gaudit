# gaudit — settled decisions

gaudit is a GNOME app that checks the security state of a computer for an ordinary user without special technical skills. The app **does not** take action itself (updating, virus scanning, etc.). It checks that things are in place and run regularly, and starts existing tools only when needed to get a status report.

This file collects decisions that have been made. Do not reopen them without a concrete reason. Write new decisions here.

## Language

- `AGENTS.md`, `TODO.md`, `notes.md` and all code comments are written in English.
- User-facing source strings (msgid) are English; see *i18n and l10n*.

## Identity

- The display name is **gAudit** and is never translated. Package, binary and text domain name is `gaudit`.
- App ID: `io.github.jeblad.gaudit`. The form `gaudit@jeblad.github.io` applies only to GNOME Shell extensions: app IDs must be reverse-DNS, and `@` is not allowed.
- App ID and name are plain variables in `CMakeLists.txt`, not cache variables, so a stale cached value can never override the identity.
- In the desktop file, `Name=gAudit`, while `GenericName` ("Security Audit") is translated.
- Contributions to gAudit itself are accepted under its license (GPL-3.0-only) only. Plugins are separate and may use any license (see *Plugins*).
- Every code and build file starts with a single `SPDX-License-Identifier: GPL-3.0-only` line, and nothing more. The full text is in `LICENSE`. Translations and test fixtures have no header.
- Developer: John Erling Blad. License: **GPL-3.0-only**. Repository: <https://github.com/jeblad/gaudit>. These are set as plain variables in `CMakeLists.txt` and shown in the About dialog.

## Goals and platform

- Language: C/C++.
- The GUI (controller and view) is written in C with GTK4/libadwaita. gtkmm was rejected: in other projects it lacked parts we needed.
- The model may be written in C++ where it pays off. The boundary to the C part is a plain C API:
  - `extern "C"` and opaque handles; no C++ types in headers the C code sees
  - no exceptions across the boundary, only status codes. Header declarations are marked `GAUDIT_NOEXCEPT` (`noexcept` in C++, empty in C) so the compiler enforces it.
  - clear memory ownership (whoever allocates, frees)
- The helper and the check processes are written in C. **Collectors that must use a C++-only library may be written in C++** (e.g. the dnf collector with libdnf5). They are separate processes, so no C++ types cross any boundary, only S-expressions over a pipe.
- First platform is the Debian family (Ubuntu, Debian and derivatives). Distro-specific logic sits behind a thin backend interface per area (`pkg`, `firewall`, `scheduler`, …), so other distros only need new backends. Next in order: **Fedora, Arch, SUSE**. Their package data is best read through their own libraries (libdnf5, libalpm, libzypp/rpm) in separate collectors, as for Flatpak.
- **Fedora backend:** detected by the rpm database, `/usr/bin/rpm` and `/usr/bin/dnf5`. Read directly: metadata age (newest `repomd.xml` under `/var/cache/libdnf5/*/repodata/`) and automatic updates (`dnf5-automatic.timer` or its alias `dnf-automatic.timer` enabled, and `apply_updates` on; the override files `/etc/dnf/automatic.conf` and `/etc/dnf/dnf5-plugins/automatic.conf` are both reserved by the package and their precedence is unknown, so if they disagree the answer is *unknown*; otherwise the packaged default `/usr/share/dnf5/dnf5-plugins/automatic.conf`, which ships `apply_updates = no`; a timer that only downloads counts as off — verified in a Fedora 45 container). Pending updates and packages without a source come from the libdnf5 collector `gaudit-dnf-probe` (C++), which reads the system cache only (`cacheonly=all`, system cachedir also as an ordinary user), lets libdnf5 apply excludes and versionlock, and leaves install-only packages (old kernels) out of "without a source". Verified in a Fedora 45 container as root and as `nobody`, against `dnf check-upgrade` and `dnf list --extras`. Repositories live in `/usr/share/dnf5/repos.d`; local changes go in `/etc/dnf/repos.override.d`. It covers Fedora and other systems with libdnf5. The RHEL family (CentOS Stream, AlmaLinux, Rocky) still uses dnf 4/libdnf, so it gets the generic backend and the "rpm is not checked" warning until there is a dnf4 variant. The expectation is set only by `ID=fedora`, not by `ID_LIKE`, because RHEL-family systems list `fedora` there and would get a false "package system missing" warning.
- **The backend is chosen by feature detection, never by the distribution's name.** Each backend has a `detect()` that checks for its package system (Debian: `/var/lib/dpkg/status` and `/usr/bin/dpkg`); the first one present is used, otherwise the generic backend, which knows only common program paths and Flatpak.
- **The distribution only sets an expectation.** `/etc/os-release` (fallback `/usr/lib/os-release`), read directly: `ID` or `ID_LIKE` naming `debian` or `ubuntu` means we expect dpkg/apt. If the expected package system is not found, Home shows a warning row ("This looks like Ubuntu, but its package system (dpkg/apt) was not found"); when it matches, the row is hidden and the heading is confirmation enough.
- **Recognising a distribution is not the same as being able to check it.** Each check finds out by trying, through the backend. A check the backend cannot do shows "Not supported on this system yet", which is different from *unknown* ("could not find out"). Such rows are never hidden: updates matter too much to disappear silently.
- **All package systems are detected, not just the one we check.** By their databases on disk (dpkg; rpm in `/var/lib/rpm` and `/usr/lib/sysimage/rpm`; pacman; Slackware pkgtools in `/var/lib/pkgtools/packages` and `/var/log/packages`; apk; Portage; XBPS; Nix; Guix), counting only signs of installed packages, not an empty database. Any present besides the backend's own gives a warning row ("Packages managed by rpm are not checked"), since their packages are invisible to every other check. Mixed systems happen.
- Home shows what was detected as "Status: <host> (<distribution> – <family>)", e.g. "Status: chimera (Ubuntu – Debian)", or "(Unknown)" when os-release gives nothing. The part after the dash is how gAudit treats the system (which backend does the checks), not something read from the distribution. The full name with version and code name is in the tooltip, because releases go out of support. These values come from the system and are shown as plain text, never as markup. The same goes for all row titles and subtitles on Home.
- Shipped as a regular distro package, **not** Flatpak. Its sandbox blocks the host access the app needs.

## User interface

- **One window with a sidebar** (`AdwNavigationSplitView`). The sidebar is on the left in LTR locales and on the right in RTL. GTK handles this automatically, so never hard-code left/right in icons or margins. Narrow windows show sidebar and content one at a time (breakpoint).
- **Sidebar look:** modelled on Secrets, but calmer. Each icon sits on a filled circle that is grey for pages that exist but are not shown, and accent-coloured only for the open page. Secrets gives every icon its own colour, which is too loud. Hover highlights the row only, so the accent colour always means "you are here".
- **Sidebar header:** no title, and a primary (hamburger) menu with *Preferences*, *Keyboard Shortcuts* and *About gAudit*. *Preferences* holds gAudit's own settings only. A plugin's parameters live on its page 1, never in the Preferences dialog.
- **The sidebar** holds the Home button and the list of plugins, **one entry per plugin** (e.g. "ClamAV", "Firewall"). Each plugin is the entry point to one part of the audit. Clicking an area on Home goes to that plugin.
- **Plugins (tasks) are registered modules** with id, title, icon, short and long explanation, dependencies and parameters. Dependencies are expressed as abstract *capabilities* that the distro backend maps to paths and packages.
- **Page 1 is the main page**, to the right of the sidebar.
  - For a plugin: the parameters for *that* plugin's run. It works like a preferences window (`AdwPreferencesPage`), with a short description and a longer explanation behind "More about this". The user is not technical, so the explanations must be good.
  - For **Home**: the system **status**, meaning what can be found out *without* triggering a more extensive run. Plugins therefore need a cheap status probe in addition to the full run.
- **Page 2 is the report** produced by the selected plugin with the given parameters. The user reaches it by moving on from page 1, and it shows the progress while the report is being produced. It slides in with a back button (`AdwNavigationView`), like the legal page in an About dialog.
- **A plugin belongs to a specific tool** (e.g. ClamAV). Plugins are grouped by category (e.g. antivirus). The app scans for which tools in a category are installed, and the sidebar shows only plugins whose tool is installed. If no tool in a category is installed, that is reported on Home.
- **Status probes never need elevated privileges.** Home only reads what an ordinary user can read, so opening the app never asks for a password.
  - Probes return language-neutral results (stable id, verdict, data); the GUI turns them into text.
  - They read the filesystem directly (paths, mtimes, apt configuration), never the output of other tools.
  - When a probe cannot tell, the verdict is *unknown*, never a guess. For example, apt's nested block syntax for `APT::Periodic::Unattended-Upgrade` is not parsed and gives *unknown*.
  - Home probe for deb packages (implemented, `src/backend/ubuntu/dpkg.c`): compare `/var/lib/dpkg/status` with `/var/lib/apt/lists/*_Packages` to find (a) installed packages no software source offers (manually downloaded `.deb`s, disabled PPAs, leftovers from older releases) and (b) pending upgrades. To avoid false alarms: candidates are chosen as apt does, including apt pinning (`/etc/apt/preferences`, `preferences.d`: version, origin and release pins, specific before general, first match wins; default priorities 500, 1 for `NotAutomatic`, 100 with `ButAutomaticUpgrades`, 100 for the installed version); negative priorities are never installed, downgrades are not counted, phased updates below 100 % are held back. "Without a source" matches apt's `local` exactly, except that versioned kernel packages (kept as fallbacks) are left out. Pinning we cannot follow (regex package patterns, unknown pin types) and partly compressed indexes give *unknown*, never a guess. The "package lists" row is worded as *when updates were last checked for*, never as the system being up to date.
  - Source of security updates (Debian family, implemented): read from the Release files apt actually fetched in `/var/lib/apt/lists`, not from `sources.list`. Any `*-security` suite from a host other than the official ones (`security.ubuntu.com`, `archive.ubuntu.com`, `ports.ubuntu.com`, `esm.ubuntu.com`, `security.debian.org`, `deb.debian.org`; exact names) is a warning, because country mirrors may lag behind. No security suite at all (e.g. Debian unstable) shows no row.
  - Not done on purpose: flagging "installed version newer than any source". It would also catch packages left from an older release whose version sorts higher (bzip2 1.0.8-6ubuntu0.1 > 1.0.8-6build2), so it cannot single out a lagging mirror.
  - Flatpak (implemented): one row, shown only when Flatpak is installed. It reads local data only (no network) and counts (a) apps that are, or whose runtime is, end-of-life (fixed by the app developers, not the user) (b) unused end-of-life refs that `flatpak uninstall --unused` removes, and (c) end-of-life runtimes no app uses that `--unused` keeps because they are pinned, e.g. an old SDK left from development (both fixable by the user). All three raise a warning. It never flags ordinary updates, because Flatpak changes constantly; pending updates need the network and belong in a plugin.
  - The Flatpak data comes from a separate collector, `gaudit-flatpak-probe`, the only part of gAudit linked against libflatpak. It runs with an empty environment except `HOME`, a 5 s timeout and a 4 KiB output limit, and prints one S-expression. If it cannot start (exit 127: `libflatpak0` missing), Home shows the row with a link to the missing-software page. Built without libflatpak, or with no Flatpak installed, there is no row. The `flatpak` package does not depend on `libflatpak0`, so the library really can be missing.
  - Snap (implemented): one row, shown only when `/usr/bin/snap` exists. Data from snapd's local REST API on `/run/snapd.socket` (readable without privileges), through a separate collector `gaudit-snap-probe` (the only part linked against json-glib), with the same runner as Flatpak. Warnings: snapd not answering (nothing keeps snaps updated), automatic refreshes held system-wide, last refresh more than 7 days ago, snaps held back by the user, and snaps in `devmode` (sandbox violations only logged; not allowed in the stable channel, so almost always a leftover from testing). `classic` snaps also have no sandbox, but by design: the store reviews it and the user opts in with `--classic`, so it is shown as information only, never a warning. Ordinary updates are never flagged.
  - Collectors share one runner and one strict S-expression parser (`src/backend/collector.c`): empty environment except `HOME`, stdin/stderr on `/dev/null`, timeout, output limit, exit 127 means a missing library.
  - Software outside any package manager (AppImages, unpacked tarballs in `/opt`, `~/Applications`, `~/.local/bin`) belongs in a separate *mining* plugin, not on Home. It looks only in known locations, never the whole disk, and reports "not managed, last changed …" rather than "outdated".
  - For now they run in the GUI process. They belong in the orchestrator once it exists.
- **Home has its own page 2 for a missing category.** If no tool in a category is installed, Home shows it as a finding (e.g. "No antivirus program found") with a "Choose one" button. It opens a Home-specific page 2 listing the known plugins in that category, each with an explanation and the install command, and one marked as recommended. This keeps uninstalled tools out of the sidebar. The plugin "software is missing" page is then only for a *partially* installed tool (e.g. ClamAV without `freshclam`).
- **Jobs keep running when the user leaves page 2,** and also when the window is closed. When a job finishes, the app shows an in-app toast that stays until dismissed (no timeout). The start button for that report on page 1 then changes to open the finished report, so it is unambiguous when page 1 has several sections.
- **By default, finished jobs are reported only with in-app toasts.**
- **Closing the window while jobs are running** brings up a dialog (`AdwAlertDialog`) with three choices:
  - *Keep running in the background:* the app stays alive without a window until the jobs finish, then exits.
  - *Stop the jobs and close:* running jobs are cancelled and recorded as cancelled in the history.
  - *Cancel:* the window stays open.
- **System notifications are used only for jobs that finish in the background**, and are kept tidy. Notifications nobody cleans up are not allowed.
  - There is at most one notification, with a fixed ID: "N unread reports".
  - It is replaced as the count changes and withdrawn when every report has been read.
  - It has a button that opens the app (as does clicking the notification itself). If all unread reports belong to one plugin, the app opens on that plugin; otherwise it opens on Home.
  - When the app is opened again, the notification is withdrawn and unread reports are shown as toasts.
- **Unread markers.** A plugin with unread reports gets a marker (badge with count) in the sidebar and on its Home row, and unread runs are marked in the history list. A report counts as read when it has been opened on page 2.
- **Reports are kept.** Like Pika Backup, page 1 points to a list of earlier runs with their status, and each run opens its report.
  - The stored format is structured data (S-expressions), and page 2 is built directly from it.
  - Markdown is produced only when a report is exported, so it never needs to be parsed.
  - Reports are stored in `~/.local/share/gaudit/reports/` with mode `0600`, because they contain system information.
  - The user's area can be modified by malware on the account, so the history is compared with the helper's root-owned log, and reports that do not match are marked.
- **A plugin can produce several reports.** Page 1 is then divided into one section per report, each with its own parameters and its own start button. Each run opens its own page 2.
- **Parameters are remembered in GSettings.**
  - Plugins cannot install their own schemas, because a schema with our ID could override ours. gaudit ships one relocatable schema, and each report gets its own path: `/io/github/jeblad/gaudit/plugins/<plugin-id>/<report-id>/`. Values are validated against the plugin's description when read.
  - dconf is writable by the user, so a compromised account can switch checks off silently. Therefore every report states which checks were switched off, and Home shows it as a finding.
- **Missing dependencies:** the app shows an explanation and the install command in a read-only field whose text can be selected and copied. The field has a copy button and an install button. Many people are not comfortable running an installation they do not understand, so the manual field must always be there. The command is always shown LTR.
- **Installation:**
  - Primary: **PackageKit** (D-Bus).
  - Fallback: `pkexec` with the backend's fixed argv (`/usr/bin/apt-get install -- <packages>`), run with `execve`. The UI must then state clearly that the fallback is used.
  - Package names always come from the backend's fixed table, never from text that can be manipulated.
- **The availability check in the GUI is for user experience only.** It decides what is shown; the helper re-checks everything and decides.

## Plugins

The app can be extended with new audit methods, but an extension must never be able to change existing methods. That cannot be guaranteed when plugin code runs in the same process, so the boundary is between processes and data:

- **No plugin code is loaded into the GUI or the helper** (no `dlopen`). A plugin consists of:
  - a declarative description: id, title, explanations, parameters, capabilities and translations. The GUI builds pages generically from it.
  - a collector: a separate program the helper starts with privileges dropped. It uses the same protocol as the built-in checks.
  - Guile rules that run in the sandbox, in their own environment.
- **Namespaces.** `core.*` is reserved for the core key. Each owner has its own namespace and cannot use others'. The registry rejects an id that already exists, and any attempt to override.
- **Plugins can only add.** A plugin can add findings and make the overall status worse. It can never hide, change or downgrade others' findings.
- **Privileges are declared.** The helper never gives a collector more than its description states.
- **System-wide and root-owned only** (`/usr/share/gaudit/plugins/`). Plugins in the user's area are never loaded.
- The built-in tasks should use the same format, marked `core`, so there is only one code path to keep secure.
- **Authorization.** Our own plugins and plugins from owners on the signed trust list are authorized by that list, however they were obtained. Authorization follows from the signature and the list, never from the download path. Any plugin, whatever its origin, can be deauthorized by the user. That only removes the user's own access to run it.
  - *Authorize*, *Unauthorize* and *Delete* all go through the helper and require the administrator password. Switching a check off is exactly what malware would want to do.
  - Home always shows a deauthorized plugin as a finding (e.g. "ClamAV is not authorized"), so the change is never invisible.
  - Reports are kept when a plugin is deauthorized.
- **Semi-blocked plugins and local approval.** Every plugin whose owner is not on the signed trust list is semi-blocked: the user may download it, but it is not loaded until the user approves it locally. A locally approved plugin is loaded, and it is marked "locally approved" wherever it appears, including the sidebar, page 0 and its findings.
  - Approval goes through the helper and requires the administrator password (polkit `auth_admin`), so malware on the user account cannot approve its own plugin.
  - Approvals are stored root-owned (`/etc/gaudit/approved-plugins`). Each approval binds the owner's key, plugin id, version and digest, so a new version must be approved again.
  - After approval, the helper installs the plugin root-owned, even if the user downloaded it to their own area.
  - All other plugin rules still apply: own namespace, add-only findings, declared privileges.
- **Plugin menu.** The content header, next to the window buttons, has a ⋮ menu (`view-more-symbolic`) for the plugin being shown. It holds *Authorize*/*Unauthorize* (the label follows the state), *Delete*, and an item that reopens page 0. Home has no plugin menu.
- **Page 0 – about the plugin.** It is shown while a plugin is not authorized (the plugin cannot run until it is), and the first time an authorized plugin is opened. gAudit renders it from the plugin description, as plain text only: no markup and no links, so a plugin cannot imitate gAudit's own UI. A button leads on to page 1.
- **Plugin legal information lives on page 0, not in gAudit's About dialog.** The plugin's page 0 text must include its license, copyright and owner, so the About dialog does not fill up with plugin sections. Libraries are never listed, neither a plugin's nor gAudit's own: traversing the dependency tree would be far too extensive.
- **Plugin licensing is open.** A plugin may use any license, compatible with GPL or not. gAudit does not police this. Plugins talk to gAudit only through processes and data (the description format and the pipe protocol), never by linking, so the formats should be documented as a public interface. Security stays closed by default (see the trust list); "open" here means licensing only.
- Deliberate limitation: complex, custom actions in the UI are not possible. Parameter types are extended as needed (switch, choice, path, …).

### Trust: list of trusted owners

- We publish a **signed list of trusted owners**, signed with the core key. It has the same protection as the manifest: increasing version number, expiry date and rejection of older versions.
- Each entry holds the owner's name, repo URL, public key(s) and namespace.
- Owners sign their own plugins. The repo URL in the plugin's signed description must match the list.
- **We do not audit plugins.** The list only says who the owner is, not that the code has been reviewed.
- **Origin is always shown.** The UI shows repo and owner for every plugin and every finding, and states clearly that the plugin has not been reviewed by gAudit.
- **Revocation.** When an owner is removed from the list, their plugins are no longer loaded, and the user gets a clear explanation.
- We expect few owners, so the list is maintained by hand.

## Threat model

We program defensively and assume an infected machine may try to produce misleading results or hide programs.

- **We protect against:** a compromised user account, common malware, and manipulation from the user's area, for example `.desktop` overrides in `~/.local/share/applications/`, environment variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `GTK_MODULES`, `GIO_EXTRA_MODULES`, `GUILE_LOAD_PATH`) and modified rule files.
- **We try to detect, but promise nothing about:** a compromised root. We look for inconsistencies and deviations from packages, and on suspicion recommend a check from bootable USB.
- **Out of scope:** well-hidden kernel rootkits and firmware attacks.
- A green result means "no signs found", not "the machine is clean". The UI and documentation must say so honestly.

## Process and privilege model

```text
GUI (user)  ──>  orchestrator (user)
                   ├─ privileged helper (pkexec, C, minimal)
                   │     └─ fork → check processes (C, privileges dropped per check)
                   │            └─ write S-expressions to a pipe
                   └─ rule engine (Guile, sandbox, no privileges)
                          └─ data in → verdict + explanation out
```

- The GUI always runs as the ordinary user and contains no security logic. It only shows finished verdicts.
- Privileged operations are done by a small, separate helper started via **polkit/pkexec**, never setuid.
- Each check process does this at startup:
  - `setresuid`/`setresgid` to the least privileged user possible
  - drops capabilities it does not need (libcap)
  - sets `PR_SET_NO_NEW_PRIVS`
  - installs a seccomp filter
  - closes inherited file descriptors
  - clears the environment completely
- Programs are started with `execve` and absolute paths, never `system()`/`popen()`, and an inherited `PATH` is never trusted.
- All data from child processes is untrusted input, with a size limit and a strict format.
- Data is read directly from `/proc`, `/sys` and configuration files where possible, instead of parsing output from external tools.
- Independent sources for the same fact are compared, e.g. `/proc` vs `ps`, `/proc/modules` vs `/sys/module`, `/proc/net` vs `ss`. Discrepancies are reported as findings.

## Rule engine: Guile

- Reports are evaluated and explained with Guile (`guile-3.0` from Ubuntu), so evaluation can change without recompiling. Python was rejected because it pulls in too much.
- Guile runs in a separate process without privileges and with seccomp. It has no network or file access; rules receive their content over a pipe.
- Rules are evaluated with `ice-9 sandbox` (`eval-in-sandbox`), with a restricted set of bindings and time and memory limits. Rules do no I/O.
- Check data is parsed with `read` on size-limited input. The reader is never extended, and incoming data is never evaluated.

## Signed manifest

- All Guile files and our own code (helper, orchestrator, GUI) have a digest in a manifest that is re-signed on every repo update. The manifest and files may live in the user's area, because the signature provides integrity.
- **The privileged helper verifies:**
  - The public key is built in or installed root-owned from the package (`/usr/share/gaudit/keys/`), never from the user's area.
  - The manifest has an increasing version number. A version lower than the last seen or the built-in minimum is rejected.
  - The manifest has an expiry date (like `Valid-Until`). An expired manifest is reported.
  - Each line binds path, size and digest. Only files listed in the manifest are loaded. Extra files are reported, and missing files are a finding.
  - Each file is read into memory once, and the digest is checked on the same bytes that are passed on. It is never reopened after verification.
  - If files or the manifest are missing, the app falls back to the rules shipped with the package and says so clearly.
- Signing: Ed25519 via libsodium. No GPG. The signing key is kept offline, and we need a key rotation plan, e.g. accepting two keys during a transition period.

## Integrity of the app itself

- A binary cannot verify itself. Checks are done by another component, and the helper is the anchor.
- The helper:
  - verifies GUI, orchestrator and rule engine against the manifest
  - inspects `/proc/<pid>/exe`, `/proc/<pid>/maps` and the environment of the orchestrator and rule engine
  - checks `/etc/ld.so.preload` and `.desktop` overrides
- The helper writes results to a root-owned log (`/var/log/gaudit/`), so a forged GUI can be exposed afterwards.
- Signs that the app has been modified must always raise a warning.

## Linking and dependencies

- **Everything links dynamically against Ubuntu packages.** Static linking was rejected as the general rule, because it would require us to track security updates in third-party code ourselves. We do not have capacity for that.
- The helper is kept minimal and depends only on glibc and libsodium.
- Trust levels:
  1. **Our own code:** verified with the signed manifest.
  2. **Ubuntu packages:** verified with `dpkg --verify`. This catches user-level changes and clumsy root changes, but dpkg's md5sums are not signed after installation. A deeper check following apt's signed chain (`InRelease` → `Packages` → `.deb`) is optional and comes later.
  3. **Running processes:** `maps` is checked against an expected library list, derived from the packages rather than maintained by hand.

## Example checks

- Updates: when they last ran, whether automatic updates are on, and whether security updates are pending.
- Firewall: ufw/nftables (firewalld later), and whether it is actually active.
- Antivirus: whether ClamAV is installed, whether `freshclam` updates, and whether a scheduled scan exists (systemd timer or cron).
- Disk encryption (LUKS) and Secure Boot.
- Screen lock, automatic login, SSH server and services listening externally.
- Signs of tampering: `/etc/ld.so.preload`, unknown kernel modules, and whether the kernel is "tainted".

## i18n and l10n

- gettext with text domain `gaudit`. Source strings (msgid) are English; the first translation is `nb`.
- More translations are deferred. The maintainer can review nb, nn, da and sv; any other language needs a native reviewer before it ships.
- `po/` holds `POTFILES.in`, `LINGUAS` (one language code per line), `gaudit.pot` and `<lang>.po`.
- `.desktop` and polkit files are translated with `msgfmt --desktop`/`--xml`. Ubuntu ships no ITS rules for polkit, so our own are in `po/its/`, found via `GETTEXTDATADIRS`.
- **Only the presentation layer translates.** The protocol between processes and the helper's output are language-neutral, with stable keys such as `firewall.active`. The helper never translates: it runs as root, and locale from the user environment is not trustworthy there.
- Guile rules return message IDs and parameters; the GUI translates. Translatable strings in rule files are extracted with xgettext (Scheme).
- **Translations are part of integrity.** A modified `.mo` file can make a red finding read as green. Therefore:
  - The locale directory is compiled in; no environment variable can override it.
  - `.mo` files are verified like other package files.
  - Translations downloaded together with rules must be listed in the signed manifest.
- New or changed text: `cmake --build --preset default --target update-po`, then translate in `po/*.po`.

## Layout

```text
src/gui/           GUI in C (controller: gaudit-app, view: gaudit-window, task pages)
src/model/         model in C++ behind a C API (include/gaudit/model.h)
src/backend/       distro interfaces (include/gaudit/backend.h), os-release, collector runner, debian/, fedora/, generic/
src/probe/         unprivileged status probes for Home (include/gaudit/probe.h), no GTK
src/collectors/    separate collector programs (flatpak/: libflatpak, snap/: json-glib, dnf/: libdnf5, C++)
src/helper/        privileged helper (pkexec)
src/orchestrator/  orchestrator (user)
src/engine/        rule engine (Guile)
data/              .desktop and polkit policy (templates with @VAR@)
po/                translations; its/ holds ITS rules for polkit
cmake/I18n.cmake   gettext targets: pot, update-po, translations
tests/             hand-written tests
```

- Helper, orchestrator and engine are installed in `libexec/gaudit/`. `Exec` in the desktop file and `exec.path` in the polkit policy are absolute paths.
- Dependencies to install when first used: `guile-3.0-dev`, `libsodium-dev`, `libcap-dev`. `libseccomp-dev`, GTK4 and libadwaita are already present. `libflatpak-dev` is optional at build time; at run time the collector needs `libflatpak0`.

## Versioning and releases

- The version lives in `VERSION` (one line, e.g. `0.1.0`). `CMakeLists.txt` reads it into `project()`, so it reaches `config.h`, the About dialog and the `.pot` header.
- Releases use **commit-and-tag-version** (configured in `.versionrc.json`). It bumps `VERSION`, updates `CHANGELOG.md`, commits and tags `vX.Y.Z`. The maintainer runs it, because it writes git history.
- Commit messages follow **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:` …; `!` or `BREAKING CHANGE:` for breaking changes), since the changelog and the version bump are derived from them. Below 1.0.0, breaking changes bump the minor version.
- The project stays on 0.x until it is reasonably functional. 1.0.0 is a deliberate step (`--release-as 1.0.0`); the tool never reaches it by itself.
- Run the tool with a pinned version (`npx commit-and-tag-version@<exact version>`), never an unpinned `npx` download.

## Build and test

- CMake with presets:
  - `CMakePresets.json` (tracked) defines `dev` and `release`.
  - `CMakeUserPresets.json` (local, git-ignored) defines `default`, inheriting `dev`.
- Commands:
  - configure: `cmake --preset default`
  - build: `cmake --build --preset default`
  - test: `ctest --preset default`
- Parallelism is capped at 6 build jobs and 4 test jobs, because the machine has only 16 GB RAM. Never use unbounded `-j` or `--parallel`.
- `GAUDIT_DEVELOPER_BUILD=ON` (in `dev`) reads translations from the build tree. Never use it for packaging.
- Hardening is on for all targets: stack protector, stack clash protection, CET, `_FORTIFY_SOURCE=3` (not in Debug), PIE and full RELRO with `BIND_NOW`.
- Targeted, hand-written tests over clear execution paths, not a heavyweight test framework.
- **Other distributions are tested in two layers:**
  - In every normal session, backends for other distributions are tested against small fixtures in `tests/data/` (e.g. an rpm database and dnf metadata taken once from a container). They need no container and run with `ctest`.
  - Real runs happen on demand with `tools/distro-test.sh fedora|arch|opensuse|debian`, never as part of `ctest`. It uses rootless podman (no root daemon; docker is not used), mounts the source read-only, builds and tests inside a `--rm` container, runs `gaudit-probe-dump`, and removes the image afterwards, so nothing stays on disk. Disk space is needed for other things.

## Open questions

- What happens to a plugin's reports when the plugin is deleted. Deferred.

- Granularity of plugin trust. Today the signed list approves *owners*, and revocation works per owner. For owners we do not know, should approval also cover the specific plugin and version? Still under consideration.
- Hard revocation versus semi-blocking. With semi-blocking, an owner removed from the trust list becomes "unknown", and the user could approve their plugins locally. Should there also be an explicit block list in the signed file, which local approval cannot override?

- Manifest and signature format: signify/minisign-compatible or our own simple format.
- Digest algorithm: SHA-256 or BLAKE2b.
