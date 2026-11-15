/* SPDX-License-Identifier: GPL-3.0-only */
/* Writing configuration as root, on a tree built here (owned by whoever
 * runs the test, standing in for root): gAudit creates and replaces only
 * its own files, stops at anything it did not write or that changed,
 * never follows a link, refuses folders others can write, and its
 * automatic-updates drop-in is read as on by gAudit's own apt reader. */
#include "apt-conf.h"
#include "automatic.h"
#include "conf-write.h"
#include "sha256.h"

#include <fcntl.h>
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

#define CHECK_R(expr, want)                                             \
    do {                                                                \
        gaudit_conf_result got_ = (expr);                               \
        if (got_ != (want)) {                                           \
            fprintf(stderr, "%s:%d: %s gave %s, not %s\n", __FILE__,     \
                    __LINE__, #expr, gaudit_conf_result_name(got_),     \
                    gaudit_conf_result_name(want));                     \
            failures++;                                                 \
        }                                                               \
    } while (0)

static char base[] = "/tmp/gaudit-conf-XXXXXX";

static char *at(const char *rel)
{
    static char p[4][512];
    static int i;
    i = (i + 1) % 4;
    snprintf(p[i], sizeof p[i], "%s/%s", base, rel);
    return p[i];
}

static void put(const char *rel, const char *text)
{
    FILE *f = fopen(at(rel), "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

static char *get(const char *rel)
{
    static char buf[8192];
    FILE *f = fopen(at(rel), "r");
    if (f == NULL)
        return NULL;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static int exists(const char *rel)
{
    struct stat st;
    return lstat(at(rel), &st) == 0;
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

static void sha256_vectors(void)
{
    char hex[65];
    gaudit_sha256_hex("", 0, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    gaudit_sha256_hex("abc", 3, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    gaudit_sha256_hex(two, strlen(two), hex);
    CHECK(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
    static char million[1000000];
    memset(million, 'a', sizeof million);
    gaudit_sha256_hex(million, sizeof million, hex);
    CHECK(strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
}

#define TARGET GAUDIT_AUTOMATIC_PATH

int main(void)
{
    sha256_vectors();

    if (mkdtemp(base) == NULL)
        return 1;
    umask(022);
    mkdir(at("etc"), 0755);
    mkdir(at("etc/apt"), 0755);
    mkdir(at("etc/apt/apt.conf.d"), 0755);
    mkdir(at("usr"), 0755);
    mkdir(at("usr/bin"), 0755);
    mkdir(at("var"), 0755);
    mkdir(at("var/lib"), 0755);
    put("usr/bin/unattended-upgrade", "#!/bin/sh\n");
    put("etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"0\";\n");

    gaudit_conf_env env = { .root = base, .register_dir = "var/lib/gaudit", .owner = geteuid() };
    int on = -1;

    /* Off before, as the distribution's file says. */
    CHECK(gaudit_apt_unattended_upgrade(at("etc/apt/apt.conf"), at("etc/apt/apt.conf.d"), &on)
          == GAUDIT_BACKEND_OK && on == 0);

    /* Created, exactly the template, readable by all, listed. */
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_WRITTEN);
    CHECK(get(TARGET) != NULL && strcmp(get(TARGET), gaudit_automatic_content) == 0);
    struct stat st;
    CHECK(stat(at(TARGET), &st) == 0 && (st.st_mode & 07777) == 0644);
    CHECK(get("var/lib/gaudit/written") != NULL
          && strstr(get("var/lib/gaudit/written"), " core.updates.automatic on " TARGET "\n") != NULL);
    char tid[64], values[64];
    CHECK(gaudit_conf_owned(&env, TARGET, tid, values) == 1
          && strcmp(tid, GAUDIT_AUTOMATIC_TEMPLATE) == 0 && strcmp(values, "on") == 0);
    /* gAudit's reader sees it on: it comes after 20auto-upgrades. */
    CHECK(gaudit_apt_unattended_upgrade(at("etc/apt/apt.conf"), at("etc/apt/apt.conf.d"), &on)
          == GAUDIT_BACKEND_OK && on == 1);
    /* No temporary file left where apt reads. */
    CHECK(!exists("etc/apt/apt.conf.d/.gaudit-new.52gaudit-automatic-updates"));

    /* A later file turns it off again: gAudit's file stays as it is, the
     * check afterwards tells. */
    put("etc/apt/apt.conf.d/99local", "APT::Periodic::Unattended-Upgrade \"0\";\n");
    CHECK(gaudit_apt_unattended_upgrade(at("etc/apt/apt.conf"), at("etc/apt/apt.conf.d"), &on)
          == GAUDIT_BACKEND_OK && on == 0);
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_UNCHANGED);
    remove(at("etc/apt/apt.conf.d/99local"));

    /* Edited by someone: neither replaced nor removed. */
    FILE *f = fopen(at(TARGET), "a");
    fputs("// mine\n", f);
    fclose(f);
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_EDITED);
    CHECK_R(gaudit_automatic_updates_remove(&env), GAUDIT_CONF_EDITED);
    CHECK(strstr(get(TARGET), "// mine") != NULL);
    CHECK(gaudit_conf_owned(&env, TARGET, NULL, NULL) == 0);

    /* As written again: removed, and gone from the register. */
    put(TARGET, gaudit_automatic_content);
    CHECK_R(gaudit_automatic_updates_remove(&env), GAUDIT_CONF_REMOVED);
    CHECK(!exists(TARGET));
    CHECK(strstr(get("var/lib/gaudit/written"), TARGET) == NULL);
    CHECK_R(gaudit_automatic_updates_remove(&env), GAUDIT_CONF_NOT_THERE);

    /* Someone else's file of that name (or gAudit's, if the register was
     * lost in a crash): never touched. */
    put(TARGET, "// the administrator's\n");
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_FOREIGN);
    CHECK_R(gaudit_automatic_updates_remove(&env), GAUDIT_CONF_FOREIGN);
    CHECK(strcmp(get(TARGET), "// the administrator's\n") == 0);
    remove(at(TARGET));

    /* A link in its place: not followed, what it points to untouched. */
    put("outside", "outside\n");
    CHECK(symlink(at("outside"), at(TARGET)) == 0);
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_FOREIGN);
    CHECK(strcmp(get("outside"), "outside\n") == 0);
    remove(at(TARGET));

    /* Without the program the setting would do nothing: not written. */
    rename(at("usr/bin/unattended-upgrade"), at("usr/bin/away"));
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_PRECONDITION);
    CHECK(!exists(TARGET));
    rename(at("usr/bin/away"), at("usr/bin/unattended-upgrade"));

    /* A folder others can write, or a link on the way: stop. */
    chmod(at("etc/apt/apt.conf.d"), 0777);
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_UNSAFE);
    CHECK(!exists(TARGET));
    chmod(at("etc/apt/apt.conf.d"), 0755);
    rename(at("etc/apt"), at("etc/real-apt"));
    CHECK(symlink("real-apt", at("etc/apt")) == 0);
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_UNSAFE);
    CHECK(!exists("etc/real-apt/apt.conf.d/52gaudit-automatic-updates"));
    remove(at("etc/apt"));
    rename(at("etc/real-apt"), at("etc/apt"));

    /* A damaged register: nothing is trusted, nothing written. */
    put("var/lib/gaudit/written", "not a register\n");
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_ERROR);
    CHECK(!exists(TARGET));
    put("var/lib/gaudit/written", "");
    CHECK_R(gaudit_automatic_updates_on(&env), GAUDIT_CONF_WRITTEN);

    /* Preconditions on other files, and names that are refused. */
    gaudit_conf_expect absent = { "etc/apt/apt.conf.d/20auto-upgrades", GAUDIT_EXPECT_ABSENT, NULL };
    char hex[65];
    const char *auto20 = "APT::Periodic::Unattended-Upgrade \"0\";\n";
    gaudit_sha256_hex(auto20, strlen(auto20), hex);
    gaudit_conf_expect same = { "etc/apt/apt.conf.d/20auto-upgrades", GAUDIT_EXPECT_DIGEST, hex };
    gaudit_conf_plan plan = { .path = "etc/apt/apt.conf.d/53gaudit-test", .template_id = "t",
                              .values = "v", .content = "x\n", .len = 2, .mode = 0644 };
    plan.expect = &absent;
    plan.n_expect = 1;
    CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_PRECONDITION);
    plan.expect = &same;
    CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_WRITTEN);
    put("etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"1\";\n");
    plan.content = "y\n";
    CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_PRECONDITION);
    CHECK(strcmp(get("etc/apt/apt.conf.d/53gaudit-test"), "x\n") == 0);
    plan.n_expect = 0;
    const char *bad[] = { "../x", "etc/../x", "/etc/x", "etc/.hidden", "etc//x", "etc/x/", "etc/a b", "" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        plan.path = bad[i];
        CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_ERROR);
    }
    plan.path = "etc/apt/apt.conf.d/53gaudit-test";
    plan.mode = 0666;  /* never writable by others */
    CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_ERROR);
    plan.mode = 0644;
    plan.values = "Not Valid";
    CHECK_R(gaudit_conf_write(&env, &plan), GAUDIT_CONF_ERROR);

    nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    if (failures == 0)
        puts("conf-write: all checks passed");
    return failures == 0 ? 0 : 1;
}
