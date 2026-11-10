/* SPDX-License-Identifier: GPL-3.0-only */
/* Generic backend for distributions without a dedicated one. It knows only
 * what is the same everywhere: common program paths and Flatpak. Package
 * checks are not implemented, so they show as "not supported". */
#include "config.h"
#include "gaudit/backend.h"

#include "flatpak-runner.h"
#include "snap-runner.h"

#include <stddef.h>
#include <string.h>

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

/* Package names differ between distributions, so none are given. */
static const char *const no_packages[]     = { NULL };
static const char *const clamav_paths[]    = { "/usr/bin/clamscan", NULL };
static const char *const freshclam_paths[] = { "/usr/bin/freshclam", NULL };
static const char *const ufw_paths[]       = { "/usr/sbin/ufw", NULL };
static const char *const firewalld_paths[] = { "/usr/sbin/firewalld", NULL };

static const gaudit_capability capabilities[] = {
    { "clamav",    clamav_paths,    no_packages },
    { "freshclam", freshclam_paths, no_packages },
    { "ufw",       ufw_paths,       no_packages },
    { "firewalld", firewalld_paths, no_packages },
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

static gaudit_backend_status flatpak_state(gaudit_flatpak_state *out)
{
    return gaudit_flatpak_run_probe("/usr/bin/flatpak", GAUDIT_FLATPAK_PROBE_PATH, 5000, out);
}

static gaudit_backend_status snap_state(gaudit_snap_state *out)
{
    return gaudit_snap_run_probe("/usr/bin/snap", GAUDIT_SNAP_PROBE_PATH, 5000, out);
}

static const gaudit_pkg_backend generic_pkg = {
    .name = "generic",
    .own_package_system = -1,
    .package_systems_present = gaudit_package_systems_present_here,
    .private_files = gaudit_private_files_here,
    .listening = gaudit_listening_here,
    .capability = capability,
    .flatpak_state = flatpak_state,
    .snap_state = snap_state,
};

const gaudit_pkg_backend *gaudit_pkg_backend_generic(void)
{
    return &generic_pkg;
}
