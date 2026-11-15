/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"
#include "gaudit/backend.h"

#include "apt-conf.h"
#include "apt-sources.h"
#include "dpkg.h"
#include "flatpak-runner.h"
#include "snap-runner.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
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
static const char *const libjson_glib_pkgs[] = { "libjson-glib-1.0-0", NULL };

static const gaudit_capability capabilities[] = {
    { "clamav",    clamav_paths,    clamav_pkgs },
    { "freshclam", freshclam_paths, freshclam_pkgs },
    { "ufw",       ufw_paths,       ufw_pkgs },
    { "firewalld", firewalld_paths, firewalld_pkgs },
    { "libflatpak", no_paths,       libflatpak_pkgs },
    { "libjson-glib", no_paths,     libjson_glib_pkgs },
};

/* The distribution's usual choice when nothing in a category is installed. */
static const char *const recommended[] = { "ufw", "clamav", NULL };

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

static gaudit_backend_status sourceless_packages(gaudit_sourceless_fn fn, void *ctx)
{
    gaudit_deb_counts counts;
    return gaudit_deb_scan_ex("/var/lib/dpkg/status", "/var/lib/apt/lists",
                              "/etc/apt/preferences", "/etc/apt/preferences.d", &counts, fn, ctx);
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

static gaudit_backend_status package_counts(unsigned *out_obsolete, unsigned *out_upgradable,
                                            unsigned *out_security)
{
    if (out_obsolete == NULL || out_upgradable == NULL || out_security == NULL)
        return GAUDIT_BACKEND_ERROR;
    gaudit_deb_counts counts;
    gaudit_backend_status status =
        gaudit_deb_scan("/var/lib/dpkg/status", "/var/lib/apt/lists",
                        "/etc/apt/preferences", "/etc/apt/preferences.d", &counts);
    if (status == GAUDIT_BACKEND_OK) {
        *out_obsolete = counts.obsolete;
        *out_upgradable = counts.upgradable;
        *out_security = counts.security;
    }
    return status;
}

/* Whether a systemd timer is on: enabled (a link in timers.target.wants)
 * and not masked; 0 when its unit is not installed at all. Read from the
 * filesystem, never from systemctl. 1, 0, or -1 when it cannot be told. */
static int timer_on(const char *name)
{
    static const char *const unit_dirs[] = { "/usr/lib/systemd/system", "/lib/systemd/system" };
    char path[256];
    struct stat st;
    int installed = 0;
    for (size_t i = 0; i < COUNT_OF(unit_dirs); i++) {
        snprintf(path, sizeof path, "%s/%s", unit_dirs[i], name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            installed = 1;
    }
    if (!installed)
        return 0;
    snprintf(path, sizeof path, "/etc/systemd/system/%s", name);
    if (lstat(path, &st) == 0) {
        char target[64];
        ssize_t n = S_ISLNK(st.st_mode) ? readlink(path, target, sizeof target - 1) : -1;
        if (n > 0) {
            target[n] = '\0';
            if (strcmp(target, "/dev/null") == 0)
                return 0;  /* masked */
        }
    }
    snprintf(path, sizeof path, "/etc/systemd/system/timers.target.wants/%s", name);
    if (lstat(path, &st) == 0)
        return 1;
    return errno == ENOENT ? 0 : -1;
}

/* apt's daily job (apt.systemd.daily) looks for updates every
 * Update-Package-Lists days and runs unattended-upgrade when
 * Unattended-Upgrade is on; both only through the two timers. */
static gaudit_backend_status update_settings(gaudit_update_settings *out)
{
    if (out == NULL)
        return GAUDIT_BACKEND_ERROR;
    const char *file = "/etc/apt/apt.conf", *dir = "/etc/apt/apt.conf.d";
    long days, install, download;
    out->check_days = gaudit_apt_periodic(file, dir, "Update-Package-Lists", &days)
                      == GAUDIT_BACKEND_OK && days >= 0 ? days : -1;
    out->download = gaudit_apt_periodic(file, dir, "Download-Upgradeable-Packages", &download)
                    == GAUDIT_BACKEND_OK ? download != 0 : -1;
    out->install = access("/usr/bin/unattended-upgrade", X_OK) != 0 ? 0
                 : gaudit_apt_periodic(file, dir, "Unattended-Upgrade", &install)
                   == GAUDIT_BACKEND_OK ? install != 0 : -1;
    out->check_timer = timer_on("apt-daily.timer");
    out->install_timer = timer_on("apt-daily-upgrade.timer");
    /* Touched each time the daily job has run unattended-upgrade. */
    struct stat st;
    if (stat("/var/lib/apt/periodic/upgrade-stamp", &st) == 0 && S_ISREG(st.st_mode))
        out->last_install = st.st_mtime;
    else
        out->last_install = errno == ENOENT ? 0 : -1;
    /* dpkg writes its status file whenever it installs, updates or removes
     * a package, by hand or automatically. */
    out->last_change = stat("/var/lib/dpkg/status", &st) == 0 && S_ISREG(st.st_mode)
                       ? st.st_mtime : -1;
    /* Graphical tools that set up or run updates, found by the package
     * database (never by a file on PATH). With one of them, gAudit leaves
     * the setting to it. */
    static const char *const tools[] = {
        "software-properties-gtk", "software-properties-qt", "update-manager", "synaptic",
        "gnome-software", "plasma-discover", "app-center", NULL,
    };
    unsigned n = 0;
    /* gAudit's own drop-in (src/plugins/updates/helper/automatic.h), so the
     * setting it made can be removed again from the app. */
    out->own_setting = lstat("/etc/apt/apt.conf.d/52gaudit-automatic-updates", &st) == 0 ? 1
                     : errno == ENOENT ? 0 : -1;
    out->admin_tools = gaudit_deb_installed_names("/var/lib/dpkg/status", tools, out->admin_names,
                                                  sizeof out->admin_names, &n) == 0 ? (int)n : -1;
    return GAUDIT_BACKEND_OK;
}

#define FLATPAK_TIMEOUT_MS 5000

static gaudit_backend_status flatpak_state(gaudit_flatpak_state *out)
{
    return gaudit_flatpak_run_probe("/usr/bin/flatpak", GAUDIT_FLATPAK_PROBE_PATH,
                                    FLATPAK_TIMEOUT_MS, out);
}

static gaudit_backend_status security_sources(unsigned *out_official, unsigned *out_mirror,
                                              char *host, size_t host_len)
{
    return gaudit_apt_security_sources("/var/lib/apt/lists", out_official, out_mirror,
                                       host, host_len);
}

static int detect(void)
{
    return gaudit_deb_present("/var/lib/dpkg/status", "/usr/bin/dpkg");
}

static gaudit_backend_status snap_state(gaudit_snap_state *out)
{
    return gaudit_snap_run_probe("/usr/bin/snap", GAUDIT_SNAP_PROBE_PATH, FLATPAK_TIMEOUT_MS, out);
}

static const gaudit_pkg_backend debian_pkg = {
    .name = "debian",
    .package_system = "dpkg/apt",
    .detect = detect,
    .own_package_system = GAUDIT_PKGSYS_DPKG,
    .package_systems_present = gaudit_package_systems_present_here,
    .listening = gaudit_listening_here,
    .recommended = recommended,
    .manual_install_command = "sudo apt install",
    .fallback_install_argv = fallback_argv,
    .capability = capability,
    .last_index_update = last_index_update,
    .automatic_updates = automatic_updates,
    .package_state = package_state,
    .package_counts = package_counts,
    .update_settings = update_settings,
    .sourceless_packages = sourceless_packages,
    .flatpak_state = flatpak_state,
    .snap_state = snap_state,
    .security_sources = security_sources,
};

const gaudit_pkg_backend *gaudit_pkg_backend_debian(void)
{
    return &debian_pkg;
}
