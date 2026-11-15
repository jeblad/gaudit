/* SPDX-License-Identifier: GPL-3.0-only */
/* The apt operations of the Updates fix pages: the command a page shows
 * is the helper's argv, word for word, and only plain names of installed
 * packages ever reach a reinstall. */
#include "apt.h"
#include "apt-ops.h"

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

static int shown_is(const char *name, const char *const *pkgs, size_t n, const char *want)
{
    char buf[1024];
    const gaudit_apt_op *op = gaudit_apt_op_find(name);
    if (op == NULL || gaudit_apt_op_shown(op, pkgs, n, buf, sizeof buf) != 0) {
        fprintf(stderr, "%s: not shown\n", name);
        return 0;
    }
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "%s: shown \"%s\"\n", name, buf);
        return 0;
    }
    /* Word for word the helper's argv, the program by its name. */
    size_t i = 0;
    char copy[1024];
    snprintf(copy, sizeof copy, "%s", buf);
    char *save = NULL;
    char *word = strtok_r(copy, " ", &save);  /* "sudo" */
    for (word = strtok_r(NULL, " ", &save); word != NULL && op->argv[i] != NULL;
         word = strtok_r(NULL, " ", &save), i++) {
        const char *expect = i == 0 ? strrchr(op->argv[0], '/') + 1 : op->argv[i];
        if (strcmp(word, expect) != 0)
            return 0;
    }
    return op->argv[i] == NULL;
}

static char dir[] = "/tmp/gaudit-apt-XXXXXX";

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

int main(void)
{
    CHECK(shown_is("apt-update", NULL, 0, "sudo apt-get update"));
    CHECK(shown_is("apt-upgrade", NULL, 0,
                   "sudo apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
                   " --with-new-pkgs upgrade"));
    CHECK(shown_is("apt-upgrade-update", NULL, 0,
                   "sudo apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
                   " --with-new-pkgs upgrade --update"));
    CHECK(shown_is("enable-apt-timers", NULL, 0,
                   "sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer"));
    const char *pkgs[] = { "openssh-server", "libc6:amd64" };
    char buf[1024];
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("reinstall"), pkgs, 2, buf, sizeof buf) == 0
          && strcmp(buf, "sudo apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
                         " install --reinstall openssh-server libc6:amd64") == 0);
    /* Never anything but a plain name in a command. */
    const char *bad[] = { "-y", "a;b", "A", "x", "a b", "a:", "a:B", "../x", "$(id)" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        CHECK(!gaudit_apt_plain_package(bad[i]));
        CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("reinstall"), &bad[i], 1, buf, sizeof buf) != 0);
    }
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("apt-update"), pkgs, 1, buf, sizeof buf) != 0);
    CHECK(gaudit_apt_op_find("rm") == NULL && gaudit_apt_op_find(NULL) == NULL);

    /* Installed means dpkg has its file list. */
    if (mkdtemp(dir) == NULL)
        return 1;
    char path[256];
    snprintf(path, sizeof path, "%s/openssh-server.list", dir);
    FILE *f = fopen(path, "w");
    if (f != NULL)
        fclose(f);
    snprintf(path, sizeof path, "%s/libc6:amd64.list", dir);
    f = fopen(path, "w");
    if (f != NULL)
        fclose(f);
    CHECK(gaudit_apt_package_ok("openssh-server", dir));
    CHECK(gaudit_apt_package_ok("libc6:amd64", dir));
    CHECK(!gaudit_apt_package_ok("vim", dir));
    CHECK(!gaudit_apt_package_ok("-y", dir));
    /* The helper refuses an unknown operation, or packages where none belong. */
    char *p[] = { (char *)"vim" };
    CHECK(gaudit_apt_run("rm", NULL, 0) == -1);
    CHECK(gaudit_apt_run("apt-update", p, 1) == -1);
    CHECK(gaudit_apt_run("reinstall", NULL, 0) == -1);
    nftw(dir, rm_one, 8, FTW_DEPTH | FTW_PHYS);

    if (failures == 0)
        puts("apt-ops: all checks passed");
    return failures == 0 ? 0 : 1;
}
