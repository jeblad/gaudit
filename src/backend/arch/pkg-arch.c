/* SPDX-License-Identifier: GPL-3.0-only */
/* Arch backend: pacman. The sync database age is read from files; pending
 * updates and foreign packages come from the libalpm collector. Arch has
 * no automatic updates by design, so that row shows "not supported". */
#include "config.h"
#include "gaudit/backend.h"

#include "flatpak-runner.h"
#include "pacman-files.h"
#include "pacman-runner.h"
#include "snap-runner.h"

#include <stddef.h>
#include <string.h>

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))
#define COLLECTOR_TIMEOUT_MS 5000
#define PACMAN_TIMEOUT_MS    20000

static const char *const clamav_paths[]    = { "/usr/bin/clamscan", NULL };
static const char *const clamav_pkgs[]     = { "clamav", NULL };
static const char *const freshclam_paths[] = { "/usr/bin/freshclam", NULL };
static const char *const ufw_paths[]       = { "/usr/bin/ufw", NULL };
static const char *const ufw_pkgs[]        = { "ufw", NULL };
static const char *const firewalld_paths[] = { "/usr/bin/firewalld", NULL };
static const char *const firewalld_pkgs[]  = { "firewalld", NULL };
static const char *const no_paths[]        = { NULL };
static const char *const flatpak_pkgs[]    = { "flatpak", NULL };
static const char *const json_glib_pkgs[]  = { "json-glib", NULL };
static const char *const pacman_pkgs[]     = { "pacman", NULL };

/* On Arch, freshclam is part of the clamav package; ufw and firewalld live
 * in /usr/bin (merged /usr/sbin). */
static const gaudit_capability capabilities[] = {
    { "clamav",       clamav_paths,    clamav_pkgs },
    { "freshclam",    freshclam_paths, clamav_pkgs },
    { "ufw",          ufw_paths,       ufw_pkgs },
    { "firewalld",    firewalld_paths, firewalld_pkgs },
    { "libflatpak",   no_paths,        flatpak_pkgs },
    { "libjson-glib", no_paths,        json_glib_pkgs },
    { "libalpm",      no_paths,        pacman_pkgs },
};

static const char *const fallback_argv[] = {
    "/usr/bin/pkexec", "/usr/bin/pacman", "-S", "--noconfirm", "--needed", "--", NULL
};

static const gaudit_capability *capability(const char *id)
{
    if (id == NULL)
        return NULL;
    for (size_t i = 0; i < COUNT_OF(capabilities); i++)
        if (strcmp(capabilities[i].id, id) == 0)
            return &capabilities[i];
    return NULL;
}

static int detect(void)
{
    return gaudit_arch_present("");
}

static gaudit_backend_status last_index_update(int64_t *out_epoch)
{
    return gaudit_pacman_sync_time("/var/lib/pacman/sync", out_epoch);
}

static gaudit_backend_status package_state(unsigned *out_obsolete, unsigned *out_upgradable)
{
    if (out_obsolete == NULL || out_upgradable == NULL)
        return GAUDIT_BACKEND_ERROR;
    gaudit_pacman_state st;
    gaudit_backend_status status =
        gaudit_pacman_run_probe("/usr/bin/pacman", GAUDIT_PACMAN_PROBE_PATH, PACMAN_TIMEOUT_MS, &st);
    if (status == GAUDIT_BACKEND_OK) {
        *out_obsolete = st.foreign;
        *out_upgradable = st.upgradable;
    }
    return status;
}

static gaudit_backend_status flatpak_state(gaudit_flatpak_state *out)
{
    return gaudit_flatpak_run_probe("/usr/bin/flatpak", GAUDIT_FLATPAK_PROBE_PATH,
                                    COLLECTOR_TIMEOUT_MS, out);
}

static gaudit_backend_status snap_state(gaudit_snap_state *out)
{
    return gaudit_snap_run_probe("/usr/bin/snap", GAUDIT_SNAP_PROBE_PATH,
                                 COLLECTOR_TIMEOUT_MS, out);
}

static const gaudit_pkg_backend arch_pkg = {
    .name = "arch",
    .package_system = "pacman",
    .detect = detect,
    .own_package_system = GAUDIT_PKGSYS_PACMAN,
    .package_systems_present = gaudit_package_systems_present_here,
    .private_files = gaudit_private_files_here,
    .listening = gaudit_listening_here,
    .manual_install_command = "sudo pacman -S --needed",
    .fallback_install_argv = fallback_argv,
    .capability = capability,
    .last_index_update = last_index_update,
    .package_state = package_state,
    .flatpak_state = flatpak_state,
    .snap_state = snap_state,
};

const gaudit_pkg_backend *gaudit_pkg_backend_arch(void)
{
    return &arch_pkg;
}
