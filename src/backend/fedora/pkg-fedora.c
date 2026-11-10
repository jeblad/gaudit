/* SPDX-License-Identifier: GPL-3.0-only */
/* Fedora backend: rpm + dnf5. Package metadata age and automatic updates
 * are read from files; pending updates and packages without a source come
 * from the libdnf5 collector (not implemented yet). */
#include "config.h"
#include "gaudit/backend.h"

#include "dnf-files.h"
#include "flatpak-runner.h"
#include "snap-runner.h"

#include <stddef.h>
#include <string.h>

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))
#define COLLECTOR_TIMEOUT_MS 5000

static const char *const clamav_paths[]    = { "/usr/bin/clamscan", NULL };
static const char *const clamav_pkgs[]     = { "clamav", NULL };
static const char *const freshclam_paths[] = { "/usr/bin/freshclam", NULL };
static const char *const freshclam_pkgs[]  = { "clamav-update", NULL };
static const char *const ufw_paths[]       = { "/usr/sbin/ufw", NULL };
static const char *const ufw_pkgs[]        = { "ufw", NULL };
static const char *const firewalld_paths[] = { "/usr/sbin/firewalld", NULL };
static const char *const firewalld_pkgs[]  = { "firewalld", NULL };
static const char *const no_paths[]        = { NULL };
static const char *const libflatpak_pkgs[] = { "flatpak-libs", NULL };
static const char *const json_glib_pkgs[]  = { "json-glib", NULL };

static const gaudit_capability capabilities[] = {
    { "clamav",       clamav_paths,    clamav_pkgs },
    { "freshclam",    freshclam_paths, freshclam_pkgs },
    { "ufw",          ufw_paths,       ufw_pkgs },
    { "firewalld",    firewalld_paths, firewalld_pkgs },
    { "libflatpak",   no_paths,        libflatpak_pkgs },
    { "libjson-glib", no_paths,        json_glib_pkgs },
};

static const char *const fallback_argv[] = {
    "/usr/bin/pkexec", "/usr/bin/dnf", "install", "-y", "--", NULL
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
    return gaudit_fedora_present("");
}

static gaudit_backend_status last_index_update(int64_t *out_epoch)
{
    return gaudit_dnf_cache_time("/var/cache/libdnf5", out_epoch);
}

static gaudit_backend_status automatic_updates(int *out_enabled)
{
    return gaudit_dnf_automatic("", out_enabled);
}

static gaudit_backend_status package_state(unsigned *out_obsolete, unsigned *out_upgradable)
{
    (void)out_obsolete;
    (void)out_upgradable;
    return GAUDIT_BACKEND_NOT_IMPLEMENTED;  /* comes with the libdnf5 collector */
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

static const gaudit_pkg_backend fedora_pkg = {
    .name = "fedora",
    .package_system = "rpm/dnf",
    .detect = detect,
    .own_package_system = GAUDIT_PKGSYS_RPM,
    .package_systems_present = gaudit_package_systems_present_here,
    .manual_install_command = "sudo dnf install",
    .fallback_install_argv = fallback_argv,
    .capability = capability,
    .last_index_update = last_index_update,
    .automatic_updates = automatic_updates,
    .package_state = package_state,
    .flatpak_state = flatpak_state,
    .snap_state = snap_state,
};

const gaudit_pkg_backend *gaudit_pkg_backend_fedora(void)
{
    return &fedora_pkg;
}
