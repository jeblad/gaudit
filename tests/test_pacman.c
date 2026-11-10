/* SPDX-License-Identifier: GPL-3.0-only */
/* Arch backend files (detection, sync database age, pacman.conf) and the
 * pacman collector protocol. Trees with modes and mtimes are built at run
 * time under the build directory. */
#include "pacman-files.h"
#include "pacman-runner.h"

#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int failures;

static int remove_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define DATA GAUDIT_TEST_DATA_DIR "/pacman"
#define PRESENT "/bin/sh"  /* stands in for /usr/bin/pacman */

static char base[1024];

static void mkdirs(const char *rel)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    for (char *p = path + strlen(base) + 1; *p != '\0'; p++)
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    mkdir(path, 0755);
}

static void put(const char *rel, mode_t mode, time_t mtime)
{
    char path[2048], dir[2048];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    snprintf(dir, sizeof dir, "%s", rel);
    char *slash = strrchr(dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        mkdirs(dir);
    }
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        exit(1);
    }
    fputs("x", f);
    fclose(f);
    chmod(path, mode);
    if (mtime != 0) {
        struct timespec t[2] = { { mtime, 0 }, { mtime, 0 } };
        utimensat(AT_FDCWD, path, t, 0);
    }
}

static const char *root(const char *name)
{
    static char path[2048];
    snprintf(path, sizeof path, "%s/%s", base, name);
    return path;
}

/* Index of word in a NUL-separated list, -1 if absent; *n gets the count. */
static int find(const char *list, const char *word, int *n)
{
    int i = 0, at = -1;
    for (const char *p = list; *p != '\0'; p += strlen(p) + 1, i++)
        if (at < 0 && strcmp(p, word) == 0)
            at = i;
    *n = i;
    return at;
}

int main(void)
{
    snprintf(base, sizeof base, "%s/pacman-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    /* Detection: package entries plus an executable pacman. */
    put("ok/var/lib/pacman/local/bash-5.2-1/desc", 0644, 0);
    put("ok/var/lib/pacman/local/ALPM_DB_VERSION", 0644, 0);
    put("ok/usr/bin/pacman", 0755, 0);
    CHECK(gaudit_arch_present(root("ok")) == 1);
    put("empty/var/lib/pacman/local/ALPM_DB_VERSION", 0644, 0);  /* version file only */
    put("empty/usr/bin/pacman", 0755, 0);
    CHECK(gaudit_arch_present(root("empty")) == 0);
    put("noexec/var/lib/pacman/local/bash-5.2-1/desc", 0644, 0);
    put("noexec/usr/bin/pacman", 0644, 0);
    CHECK(gaudit_arch_present(root("noexec")) == 0);

    /* Sync database age: the newest .db counts, nothing else does. */
    time_t now = time(NULL);
    int64_t t = 0;
    put("sync/core.db", 0644, now - 2 * 86400);
    put("sync/extra.db", 0644, now - 3600);
    put("sync/extra.files", 0644, now);
    CHECK(gaudit_pacman_sync_time(root("sync"), &t) == GAUDIT_BACKEND_OK && t == (int64_t)(now - 3600));
    mkdirs("no-dbs");
    CHECK(gaudit_pacman_sync_time(root("no-dbs"), &t) == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_pacman_sync_time(root("missing"), &t) == GAUDIT_BACKEND_UNAVAILABLE);

    /* pacman.conf: repository sections and IgnorePkg (comments dropped). */
    char repos[512], ignore[512];
    int n;
    CHECK(gaudit_pacman_conf(DATA "/pacman.conf", repos, sizeof repos, ignore, sizeof ignore)
          == GAUDIT_BACKEND_OK);
    CHECK(find(repos, "core", &n) == 0 && n == 3);
    CHECK(find(repos, "extra", &n) == 1);
    CHECK(find(repos, "my-local-repo", &n) == 2);
    CHECK(find(repos, "multilib", &n) < 0);   /* commented out */
    CHECK(find(repos, "options", &n) < 0);
    CHECK(find(ignore, "linux", &n) == 0 && n == 3);
    CHECK(find(ignore, "linux-headers", &n) == 1);
    CHECK(find(ignore, "firefox*", &n) == 2);
    CHECK(gaudit_pacman_conf(DATA "/broken.conf", repos, sizeof repos, ignore, sizeof ignore)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_pacman_conf(DATA "/no-such.conf", repos, sizeof repos, ignore, sizeof ignore)
          == GAUDIT_BACKEND_UNAVAILABLE);
    char tiny[8];
    CHECK(gaudit_pacman_conf(DATA "/pacman.conf", tiny, sizeof tiny, ignore, sizeof ignore)
          == GAUDIT_BACKEND_ERROR);  /* does not fit: an error, never a short list */

    /* Collector protocol. */
    gaudit_pacman_state st;
    CHECK(gaudit_pacman_parse("(pacman (installed 10) (upgradable 2) (foreign 1))", &st) == 0);
    CHECK(st.installed == 10 && st.upgradable == 2 && st.foreign == 1);
    CHECK(gaudit_pacman_parse("(pacman (installed 10) (upgradable 2))", &st) != 0);
    CHECK(gaudit_pacman_run_probe(PRESENT, DATA "/ok.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.installed == 900 && st.upgradable == 14 && st.foreign == 6);
    CHECK(gaudit_pacman_run_probe("/nonexistent/pacman", DATA "/ok.sh", 2000, &st)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_pacman_run_probe(PRESENT, DATA "/no-such-collector", 2000, &st)
          == GAUDIT_BACKEND_NOT_IMPLEMENTED);
    CHECK(gaudit_pacman_run_probe(PRESENT, DATA "/missing-library.sh", 2000, &st)
          == GAUDIT_BACKEND_MISSING_DEPENDENCY);
    CHECK(gaudit_pacman_run_probe(PRESENT, DATA "/inconsistent.sh", 2000, &st)
          == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s)\n", failures, base);
    else
        nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS);  /* kept on failure, to look at */
    return failures ? 1 : 0;
}
