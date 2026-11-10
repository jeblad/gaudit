/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-pacman-probe: collector for the Arch package rows on Home.
 *
 * Uses libalpm on the local and sync databases as they are (no refresh,
 * no network). Without arguments it prints one S-expression:
 *
 *   (pacman (installed N) (upgradable N) (foreign N) (above N))
 *
 *   installed   installed packages
 *   upgradable  installed packages with a newer version in a configured
 *               repository, leaving out IgnorePkg (never upgraded)
 *   foreign     installed packages no configured repository offers, as
 *               "pacman -Qm" (e.g. from the AUR)
 *   above       installed packages the repository pacman would use offers
 *               only in a lower version ("local is newer than ..."), so no
 *               update reaches them
 *
 * With "list" it prints the foreign and above packages, one per line, then
 * their count:
 *
 *   (package (name "...") (arch "...") (version "...") (group G) (offered "..."))
 *   (end (count N))
 *
 * G is gaudit_sourceless_group: 0 above the source (offered is the
 * repository's version), 1 foreign and packaged by Arch (a packager
 * address at archlinux.org: probably dropped from the repositories),
 * 2 foreign and from someone else (e.g. the AUR).
 *
 * libalpm does not read pacman.conf, so the repository names and IgnorePkg
 * come from it here; a configured repository that was never synced is an
 * error, since every package would look foreign. Exit status 127 means a
 * library is missing; any other failure exits with 1 and prints nothing. */
#include <alpm.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pacman-files.h"

#define DB_PATH   "/var/lib/pacman/"
#define SYNC_PATH "/var/lib/pacman/sync"

/* Printable ASCII only, '"' and '\\' escaped; 0 if it does not fit or has
 * anything else, so the run fails rather than passing it on. */
static int quote(const char *in, char *out, size_t len)
{
    size_t n = 0;
    if (in == NULL || len < 3)
        return 0;
    out[n++] = '"';
    for (const char *c = in; *c != '\0'; c++) {
        if (*c < 0x20 || *c > 0x7e || n + 3 >= len)
            return 0;
        if (*c == '"' || *c == '\\')
            out[n++] = '\\';
        out[n++] = *c;
    }
    out[n++] = '"';
    out[n] = '\0';
    return 1;
}

static int print_package(alpm_pkg_t *pkg, int group, const char *offered)
{
    char name[300], arch[80], version[200], from[200];
    if (!quote(alpm_pkg_get_name(pkg), name, sizeof name)
        || !quote(alpm_pkg_get_arch(pkg) != NULL ? alpm_pkg_get_arch(pkg) : "", arch, sizeof arch)
        || !quote(alpm_pkg_get_version(pkg), version, sizeof version)
        || !quote(offered != NULL ? offered : "", from, sizeof from))
        return -1;
    return printf("(package (name %s) (arch %s) (version %s) (group %d) (offered %s))\n",
                  name, arch, version, group, from) < 0 ? -1 : 0;
}

/* Packaged by Arch itself: the packager's address is at archlinux.org. */
static int by_arch(alpm_pkg_t *pkg)
{
    const char *packager = alpm_pkg_get_packager(pkg);
    return packager != NULL && strstr(packager, "@archlinux.org>") != NULL;
}

static int ignored(const char *name, const char *ignore)
{
    for (const char *p = ignore; *p != '\0'; p += strlen(p) + 1)
        if (fnmatch(p, name, 0) == 0)
            return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    int list = argc == 2 && strcmp(argv[1], "list") == 0;
    if (argc > 2 || (argc == 2 && !list))
        return 1;
    char repos[8192], ignore[8192];
    if (gaudit_pacman_conf("/etc/pacman.conf", repos, sizeof repos, ignore, sizeof ignore)
        != GAUDIT_BACKEND_OK)
        return 1;

    alpm_errno_t err;
    alpm_handle_t *handle = alpm_initialize("/", DB_PATH, &err);
    if (handle == NULL)
        return 1;

    int rc = 0;
    for (const char *repo = repos; *repo != '\0' && rc == 0; repo += strlen(repo) + 1) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s.db", SYNC_PATH, repo);
        if (n < 0 || (size_t)n >= sizeof path || access(path, R_OK) != 0)
            rc = 1;  /* never synced: we cannot tell foreign from offered */
        else if (alpm_register_syncdb(handle, repo, ALPM_SIG_USE_DEFAULT) == NULL)
            rc = 1;
    }

    unsigned installed = 0, upgradable = 0, foreign = 0, above = 0;
    if (rc == 0) {
        alpm_list_t *syncdbs = alpm_get_syncdbs(handle);
        for (alpm_list_t *i = alpm_db_get_pkgcache(alpm_get_localdb(handle)); i != NULL;
             i = alpm_list_next(i)) {
            alpm_pkg_t *pkg = i->data;
            const char *name = alpm_pkg_get_name(pkg);
            installed++;

            /* The first repository that has it is the one pacman uses. */
            alpm_pkg_t *offered = NULL;
            for (alpm_list_t *j = syncdbs; j != NULL && offered == NULL; j = alpm_list_next(j))
                offered = alpm_db_get_pkg(j->data, name);
            if (offered == NULL) {
                foreign++;
                if (list && print_package(pkg, by_arch(pkg) ? 1 : 2, NULL) != 0)
                    rc = 1;
                continue;
            }
            if (alpm_pkg_vercmp(alpm_pkg_get_version(pkg), alpm_pkg_get_version(offered)) > 0) {
                above++;
                if (list && print_package(pkg, 0, alpm_pkg_get_version(offered)) != 0)
                    rc = 1;
                continue;
            }
            if (!ignored(name, ignore) && alpm_sync_get_new_version(pkg, syncdbs) != NULL)
                upgradable++;
        }
    }
    alpm_release(handle);
    if (rc != 0)
        return rc;

    if (list)
        printf("(end (count %u))\n", foreign + above);
    else
        printf("(pacman (installed %u) (upgradable %u) (foreign %u) (above %u))\n",
               installed, upgradable, foreign, above);
    return fflush(stdout) == 0 ? 0 : 1;
}
