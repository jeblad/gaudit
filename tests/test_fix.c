/* SPDX-License-Identifier: GPL-3.0-only */
/* The Private Files fixes: they only take access away, change the file
 * itself (never what a symbolic link points to), stay beneath their root,
 * and touch only the user's own files. On a tree built here. */
#include "fix-mode.h"

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

static char base[] = "/tmp/gaudit-fix-XXXXXX";

static mode_t mode_of(const char *rel)
{
    char p[512];
    struct stat sb;
    snprintf(p, sizeof p, "%s/%s", base, rel);
    return stat(p, &sb) == 0 ? (sb.st_mode & 07777) : (mode_t)-1;
}

static void make(const char *rel, mode_t mode)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    FILE *f = fopen(p, "w");
    if (f != NULL)
        fclose(f);
    chmod(p, mode);
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    chmod(path, 0700);
    return remove(path);
}

int main(void)
{
    if (mkdtemp(base) == NULL)
        return 1;
    char sub[512], outside[512], link[512];
    snprintf(sub, sizeof sub, "%s/a", base);
    mkdir(sub, 0755);
    make("a/key", 0666);
    make("a/already", 0600);
    make("a/exec", 0775);
    snprintf(outside, sizeof outside, "%s-outside", base);
    FILE *f = fopen(outside, "w");
    if (f != NULL)
        fclose(f);
    chmod(outside, 0666);
    snprintf(link, sizeof link, "%s/a/link", base);
    CHECK(symlink(outside, link) == 0);

    /* Others' access goes, the owner's stays. */
    CHECK(gaudit_private_files_fix("make-private", base, "a/key") == 0);
    CHECK(mode_of("a/key") == 0600);
    CHECK(gaudit_private_files_fix("make-private", base, "a/exec") == 0);
    CHECK(mode_of("a/exec") == 0700);
    CHECK(gaudit_private_files_fix("make-private", base, "a/already") == 0);
    CHECK(mode_of("a/already") == 0600);

    /* Never through a symbolic link, never out of root. */
    CHECK(gaudit_private_files_fix("make-private", base, "a/link") == 1);
    struct stat sb;
    CHECK(stat(outside, &sb) == 0 && (sb.st_mode & 07777) == 0666);
    CHECK(gaudit_private_files_fix("make-private", sub, "../a/key") == 1);
    CHECK(gaudit_private_files_fix("make-private", base, "/etc/passwd") == 2);
    CHECK(gaudit_private_files_fix("make-private", base, "a/missing") == 1);

    /* The home folder loses others' write only. */
    chmod(base, 0777);
    CHECK(gaudit_private_files_fix("close-home", base, NULL) == 0);
    CHECK(mode_of("") == 0755);

    /* Only the fixes there are. */
    CHECK(gaudit_private_files_fix("open-up", base, "a/key") == 2);
    CHECK(gaudit_private_files_fix("close-home", base, "a/key") == 2);
    CHECK(gaudit_private_files_fix("make-private", "relative", "a/key") == 2);

    remove(outside);
    nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    if (failures == 0)
        puts("fix: all checks passed");
    return failures == 0 ? 0 : 1;
}
