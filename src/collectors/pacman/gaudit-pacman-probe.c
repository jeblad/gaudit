/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-pacman-probe: collector for the Arch package rows on Home.
 *
 * Uses libalpm on the local and sync databases as they are (no refresh,
 * no network) and prints one S-expression on stdout:
 *
 *   (pacman (installed N) (upgradable N) (foreign N))
 *
 *   installed   installed packages
 *   upgradable  installed packages with a newer version in a configured
 *               repository, leaving out IgnorePkg (never upgraded)
 *   foreign     installed packages no configured repository offers, as
 *               "pacman -Qm" (e.g. from the AUR)
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

static int ignored(const char *name, const char *ignore)
{
    for (const char *p = ignore; *p != '\0'; p += strlen(p) + 1)
        if (fnmatch(p, name, 0) == 0)
            return 1;
    return 0;
}

int main(void)
{
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

    unsigned installed = 0, upgradable = 0, foreign = 0;
    if (rc == 0) {
        alpm_list_t *syncdbs = alpm_get_syncdbs(handle);
        for (alpm_list_t *i = alpm_db_get_pkgcache(alpm_get_localdb(handle)); i != NULL;
             i = alpm_list_next(i)) {
            alpm_pkg_t *pkg = i->data;
            const char *name = alpm_pkg_get_name(pkg);
            installed++;

            int offered = 0;
            for (alpm_list_t *j = syncdbs; j != NULL && !offered; j = alpm_list_next(j))
                offered = alpm_db_get_pkg(j->data, name) != NULL;
            if (!offered) {
                foreign++;
                continue;
            }
            if (!ignored(name, ignore) && alpm_sync_get_new_version(pkg, syncdbs) != NULL)
                upgradable++;
        }
    }
    alpm_release(handle);
    if (rc != 0)
        return rc;

    printf("(pacman (installed %u) (upgradable %u) (foreign %u))\n", installed, upgradable, foreign);
    return fflush(stdout) == 0 ? 0 : 1;
}
