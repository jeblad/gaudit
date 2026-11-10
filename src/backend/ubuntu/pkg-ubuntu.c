/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"
#include "gaudit/backend.h"

#include "apt-conf.h"
#include "dpkg.h"
#include "flatpak-runner.h"

#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

static const char *const clamav_paths[]    = { "/usr/bin/clamscan", NULL };
static const char *const clamav_pkgs[]     = { "clamav", NULL };
static const char *const freshclam_paths[] = { "/usr/bin/freshclam", NULL };
static const char *const freshclam_pkgs[]  = { "clamav-freshclam", NULL };
static const char *const ufw_paths[]       = { "/usr/sbin/ufw", NULL };
static const char *const ufw_pkgs[]        = { "ufw", NULL };
static const char *const firewalld_paths[] = { "/usr/sbin/firewalld", NULL };
static const char *const firewalld_pkgs[]  = { "firewalld", NULL };
/* Shared library: only the package name is used (it is detected by the
 * collector failing to start, not by a path). */
static const char *const no_paths[]        = { NULL };
static const char *const libflatpak_pkgs[] = { "libflatpak0", NULL };

static const gaudit_capability capabilities[] = {
    { "clamav",    clamav_paths,    clamav_pkgs },
    { "freshclam", freshclam_paths, freshclam_pkgs },
    { "ufw",       ufw_paths,       ufw_pkgs },
    { "firewalld", firewalld_paths, firewalld_pkgs },
    { "libflatpak", no_paths,       libflatpak_pkgs },
};

static const char *const fallback_argv[] = {
    "/usr/bin/pkexec", "/usr/bin/apt-get", "install", "--", NULL
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

static int ends_with(const char *s, const char *suffix)
{
    size_t len = strlen(s), slen = strlen(suffix);
    return len >= slen && strcmp(s + len - slen, suffix) == 0;
}

/* The newest of two sources, both read directly from the filesystem:
 *  - the stamp touched after every successful "apt update"
 *    (APT::Update::Post-Invoke-Success in update-notifier-common);
 *  - the Release files in the lists directory. apt sets their mtime from the
 *    server, so they show how fresh the repository index is. */
static gaudit_backend_status last_index_update(int64_t *out_epoch)
{
    if (out_epoch == NULL)
        return GAUDIT_BACKEND_ERROR;

    int64_t newest = 0;
    struct stat st;

    if (stat("/var/lib/apt/periodic/update-success-stamp", &st) == 0 && S_ISREG(st.st_mode))
        newest = st.st_mtime;

    DIR *dir = opendir("/var/lib/apt/lists");
    if (dir != NULL) {
        int fd = dirfd(dir);
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (!ends_with(entry->d_name, "InRelease") && !ends_with(entry->d_name, "_Release"))
                continue;
            if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0
                && S_ISREG(st.st_mode) && st.st_mtime > newest)
                newest = st.st_mtime;
        }
        closedir(dir);
    }

    if (newest == 0)
        return GAUDIT_BACKEND_UNAVAILABLE;
    *out_epoch = newest;
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status automatic_updates(int *out_enabled)
{
    if (out_enabled == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access("/usr/bin/unattended-upgrade", X_OK) != 0) {
        *out_enabled = 0;
        return GAUDIT_BACKEND_OK;
    }
    return gaudit_apt_unattended_upgrade("/etc/apt/apt.conf", "/etc/apt/apt.conf.d", out_enabled);
}

static gaudit_backend_status package_state(unsigned *out_obsolete, unsigned *out_upgradable)
{
    if (out_obsolete == NULL || out_upgradable == NULL)
        return GAUDIT_BACKEND_ERROR;
    gaudit_deb_counts counts;
    gaudit_backend_status status =
        gaudit_deb_scan("/var/lib/dpkg/status", "/var/lib/apt/lists",
                        "/etc/apt/preferences", "/etc/apt/preferences.d", &counts);
    if (status == GAUDIT_BACKEND_OK) {
        *out_obsolete = counts.obsolete;
        *out_upgradable = counts.upgradable;
    }
    return status;
}

#define FLATPAK_TIMEOUT_MS 5000

static gaudit_backend_status flatpak_state(gaudit_flatpak_state *out)
{
    return gaudit_flatpak_run_probe("/usr/bin/flatpak", GAUDIT_FLATPAK_PROBE_PATH,
                                    FLATPAK_TIMEOUT_MS, out);
}

static const gaudit_pkg_backend ubuntu_pkg = {
    .name = "ubuntu",
    .manual_install_command = "sudo apt install",
    .fallback_install_argv = fallback_argv,
    .capability = capability,
    .last_index_update = last_index_update,
    .automatic_updates = automatic_updates,
    .package_state = package_state,
    .flatpak_state = flatpak_state,
};

const gaudit_pkg_backend *gaudit_pkg_backend_ubuntu(void)
{
    return &ubuntu_pkg;
}
