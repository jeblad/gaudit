/* SPDX-License-Identifier: GPL-3.0-only */
/* Which package systems have installed packages on this machine. Detected by
 * their databases on disk, independent of the distribution's name, so mixed
 * systems (e.g. rpm next to dpkg, or Nix on anything) are seen. */
#include "gaudit/backend.h"

#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char *const labels[GAUDIT_PKGSYS_COUNT] = {
    [GAUDIT_PKGSYS_DPKG]     = "dpkg/apt",
    [GAUDIT_PKGSYS_RPM]      = "rpm",
    [GAUDIT_PKGSYS_PACMAN]   = "pacman",
    [GAUDIT_PKGSYS_PKGTOOLS] = "pkgtools (Slackware)",
    [GAUDIT_PKGSYS_APK]      = "apk (Alpine)",
    [GAUDIT_PKGSYS_PORTAGE]  = "Portage (Gentoo)",
    [GAUDIT_PKGSYS_XBPS]     = "XBPS (Void)",
    [GAUDIT_PKGSYS_NIX]      = "Nix",
    [GAUDIT_PKGSYS_GUIX]     = "Guix",
};

const char *gaudit_package_system_label(gaudit_package_system s)
{
    return s >= 0 && s < GAUDIT_PKGSYS_COUNT ? labels[s] : "?";
}

static int join(char *buf, size_t len, const char *root, const char *path)
{
    int n = snprintf(buf, len, "%s%s", root, path);
    return n >= 0 && (size_t)n < len;
}

/* A regular file (symlinks followed) that is not empty. */
static int nonempty_file(const char *root, const char *path)
{
    char full[PATH_MAX];
    struct stat st;
    return join(full, sizeof full, root, path)
        && stat(full, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
}

/* A directory with at least one entry matching pattern (NULL: any entry
 * not starting with '.'), other than the names in skip. */
static int dir_has_entry(const char *root, const char *path, const char *pattern,
                         const char *skip)
{
    char full[PATH_MAX];
    if (!join(full, sizeof full, root, path))
        return 0;
    DIR *dir = opendir(full);
    if (dir == NULL)
        return 0;
    int found = 0;
    struct dirent *de;
    while (!found && (de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (skip != NULL && strcmp(de->d_name, skip) == 0)
            continue;
        found = pattern == NULL || fnmatch(pattern, de->d_name, 0) == 0;
    }
    closedir(dir);
    return found;
}

static int rpm_present(const char *root)
{
    static const char *const dbs[] = {
        "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/var/lib/rpm/Packages.db",
        "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages",
        "/usr/lib/sysimage/rpm/Packages.db", NULL
    };
    for (const char *const *db = dbs; *db != NULL; db++)
        if (nonempty_file(root, *db))
            return 1;
    return 0;
}

unsigned gaudit_package_systems_present(const char *root)
{
    if (root == NULL)
        root = "";
    unsigned mask = 0;
    if (nonempty_file(root, "/var/lib/dpkg/status"))
        mask |= 1u << GAUDIT_PKGSYS_DPKG;
    if (rpm_present(root))
        mask |= 1u << GAUDIT_PKGSYS_RPM;
    if (dir_has_entry(root, "/var/lib/pacman/local", NULL, "ALPM_DB_VERSION"))
        mask |= 1u << GAUDIT_PKGSYS_PACMAN;
    if (dir_has_entry(root, "/var/lib/pkgtools/packages", NULL, NULL)
        || dir_has_entry(root, "/var/log/packages", NULL, NULL))
        mask |= 1u << GAUDIT_PKGSYS_PKGTOOLS;
    if (nonempty_file(root, "/lib/apk/db/installed"))
        mask |= 1u << GAUDIT_PKGSYS_APK;
    if (dir_has_entry(root, "/var/db/pkg", NULL, NULL))
        mask |= 1u << GAUDIT_PKGSYS_PORTAGE;
    if (dir_has_entry(root, "/var/db/xbps", "pkgdb-*.plist", NULL))
        mask |= 1u << GAUDIT_PKGSYS_XBPS;
    if (nonempty_file(root, "/nix/var/nix/db/db.sqlite"))
        mask |= 1u << GAUDIT_PKGSYS_NIX;
    if (nonempty_file(root, "/var/guix/db/db.sqlite"))
        mask |= 1u << GAUDIT_PKGSYS_GUIX;
    return mask;
}

unsigned gaudit_package_systems_present_here(void)
{
    return gaudit_package_systems_present("");
}
