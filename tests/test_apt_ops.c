/* SPDX-License-Identifier: GPL-3.0-only */
/* The apt operations of the Updates fix pages: the command a page shows
 * is the helper's argv, word for word, only plain names of installed
 * packages ever reach a reinstall, and only a PPA the release upgrade
 * switched off is ever set up again. */
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
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("reinstall"), NULL, 0, buf, sizeof buf) != 0);

    /* A PPA: exactly one, plain. */
    const char *ppa[] = { "ppa:cappelikan/ppa", "ppa:deadsnakes/ppa" };
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("add-ppa"), ppa, 1, buf, sizeof buf) == 0
          && strcmp(buf, "sudo add-apt-repository -y ppa:cappelikan/ppa") == 0);
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("add-ppa"), ppa, 2, buf, sizeof buf) != 0);
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("add-ppa"), NULL, 0, buf, sizeof buf) != 0);
    CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("add-ppa"), pkgs, 1, buf, sizeof buf) != 0);
    CHECK(gaudit_apt_plain_ppa("ppa:a/b") && gaudit_apt_plain_ppa("ppa:kisak/kisak-mesa")
          && gaudit_apt_plain_ppa("ppa:ubuntu-toolchain-r/test"));
    const char *bad_ppa[] = {
        "cappelikan/ppa", "ppa:", "ppa:a", "ppa:a/", "ppa:/b", "ppa:a/b/c", "ppa:A/b",
        "ppa:-a/b", "ppa:a/b;id", "ppa:a/b c", "ppa:a/$(id)", "deb http://x/ y main",
        "ppa:a/../../x", "https://ppa.launchpadcontent.net/a/b/ubuntu",
    };
    for (size_t i = 0; i < sizeof bad_ppa / sizeof bad_ppa[0]; i++) {
        CHECK(!gaudit_apt_plain_ppa(bad_ppa[i]));
        CHECK(gaudit_apt_op_shown(gaudit_apt_op_find("add-ppa"), &bad_ppa[i], 1, buf, sizeof buf) != 0);
    }
    CHECK(gaudit_apt_op_find("rm") == NULL && gaudit_apt_op_find(NULL) == NULL);

    /* Installed means dpkg has its file list. */
    if (mkdtemp(dir) == NULL)
        return 1;
    char path[512];
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
    CHECK(gaudit_apt_run("add-ppa", NULL, 0) == -1);
    char *two[] = { (char *)"ppa:a/b", (char *)"ppa:c/d" };
    CHECK(gaudit_apt_run("add-ppa", two, 2) == -1);

    /* The helper sets up again only a PPA a file names that has the
     * upgrade's copy beside it. */
    CHECK(gaudit_apt_ppa_ok("ppa:cappelikan/ppa", SOURCES_DIR));
    CHECK(!gaudit_apt_ppa_ok("ppa:cappelikan/other", SOURCES_DIR));
    CHECK(!gaudit_apt_ppa_ok("ppa:legacy/x", SOURCES_DIR));  /* not a PPA's URI */
    char srcdir[300];
    snprintf(srcdir, sizeof srcdir, "%s/sources", dir);
    mkdir(srcdir, 0700);
    static const struct { const char *name, *text; } files[] = {
        /* Switched off by hand: no copy beside it. */
        { "byhand.list", "# deb http://ppa.launchpad.net/someone/tools/ubuntu noble main\n" },
        /* The old host, switched off at the upgrade. */
        { "old.list", "# deb http://ppa.launchpad.net/old/stuff/ubuntu noble main\n" },
        { "old.list.distUpgrade", "deb http://ppa.launchpad.net/old/stuff/ubuntu noble main\n" },
        /* A copy alone, its source gone. */
        { "gone.list.distUpgrade", "deb http://ppa.launchpad.net/gone/away/ubuntu noble main\n" },
        /* A name that only starts the same. */
        { "near.list", "# deb http://ppa.launchpad.net/near/stuffing/ubuntu noble main\n" },
        { "near.list.distUpgrade", "\n" },
    };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", srcdir, files[i].name);
        f = fopen(path, "w");
        if (f != NULL) {
            fputs(files[i].text, f);
            fclose(f);
        }
    }
    CHECK(gaudit_apt_ppa_ok("ppa:old/stuff", srcdir));
    CHECK(!gaudit_apt_ppa_ok("ppa:someone/tools", srcdir));
    CHECK(!gaudit_apt_ppa_ok("ppa:gone/away", srcdir));
    CHECK(!gaudit_apt_ppa_ok("ppa:near/stuff", srcdir));
    CHECK(!gaudit_apt_ppa_ok("ppa:old/stuff", "/nonexistent"));

    /* Read for this release: its Release file for the codename is in the
     * lists; one for an older release, or another PPA's, is not. */
    char lists[300], code[64];
    snprintf(lists, sizeof lists, "%s/lists", dir);
    mkdir(lists, 0700);
    static const char *const list_files[] = {
        "ppa.launchpadcontent.net_wireshark-dev_stable_ubuntu_dists_stonking_InRelease",
        "ppa.launchpad.net_old_stuff_ubuntu_dists_stonking_Release",
        "ppa.launchpadcontent.net_heyarje_makemkv-beta_ubuntu_dists_resolute_InRelease",
        "os-release",
    };
    for (size_t i = 0; i < sizeof list_files / sizeof list_files[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", lists, list_files[i]);
        f = fopen(path, "w");
        if (f != NULL) {
            if (i == 3)
                fputs("NAME=\"Ubuntu\"\nVERSION_CODENAME=stonking\nID=ubuntu\n", f);
            fclose(f);
        }
    }
    CHECK(gaudit_os_codename(path, code, sizeof code) && strcmp(code, "stonking") == 0);
    CHECK(!gaudit_os_codename("/nonexistent", code, sizeof code));
    CHECK(gaudit_apt_ppa_read("ppa:wireshark-dev/stable", lists, "stonking"));
    CHECK(gaudit_apt_ppa_read("ppa:old/stuff", lists, "stonking"));
    CHECK(!gaudit_apt_ppa_read("ppa:heyarje/makemkv-beta", lists, "stonking"));
    CHECK(gaudit_apt_ppa_read("ppa:heyarje/makemkv-beta", lists, "resolute"));
    CHECK(!gaudit_apt_ppa_read("ppa:wireshark-dev/stable", lists, ""));
    nftw(dir, rm_one, 8, FTW_DEPTH | FTW_PHYS);

    if (failures == 0)
        puts("apt-ops: all checks passed");
    return failures == 0 ? 0 : 1;
}
