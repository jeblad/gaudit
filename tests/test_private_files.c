/* SPDX-License-Identifier: GPL-3.0-only */
/* Private files in the home directory, on trees built at run time under the
 * build directory (git does not keep modes). Never looks at the real home. */
#include "private-files.h"

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static char base[1024];

#define NOGRP ((gid_t)-1)  /* no private group: group bits count as others' */

static void dir(const char *rel, mode_t mode)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    mkdir(path, 0700);
    chmod(path, mode);
}

static void file(const char *rel, const char *content, mode_t mode)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
    chmod(path, mode);
}

static const char *at(const char *rel)
{
    static char path[2048];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    return path;
}

int main(void)
{
    snprintf(base, sizeof base, "%s/private-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    uid_t me = getuid();
    char first[64];

    /* A home where everything is right. */
    dir("good", 0750);
    dir("good/.ssh", 0700);
    file("good/.ssh/id_ed25519", "x", 0600);
    file("good/.ssh/id_ed25519.pub", "x", 0644);       /* public: may be readable */
    file("good/.ssh/known_hosts", "x", 0644);          /* not secret */
    file("good/.ssh/authorized_keys", "x", 0644);      /* readable is fine, writable is not */
    file("good/.ssh/config", "x", 0644);
    dir("good/.gnupg", 0700);
    dir("good/.gnupg/private-keys-v1.d", 0700);
    file("good/.gnupg/private-keys-v1.d/ABCDEF.key", "x", 0600);
    file("good/.gnupg/pubring.kbx", "x", 0644);         /* public keyring: fine */
    file("good/.netrc", "x", 0600);
    CHECK(gaudit_private_files_check(at("good"), me, NOGRP, first, sizeof first) == 0);
    CHECK(first[0] == '\0');

    /* A home with one problem per rule. */
    dir("bad", 0750);
    dir("bad/.ssh", 0755);                                /* 1: .ssh open */
    file("bad/.ssh/id_ed25519", "x", 0644);              /* 2: key readable */
    file("bad/.ssh/id_ed25519.pub", "x", 0644);          /*    fine */
    file("bad/.ssh/work_key", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 0640);  /* 3: by content */
    file("bad/.ssh/notes.txt", "just text\n", 0644);     /*    fine: not a key */
    file("bad/.ssh/authorized_keys", "x", 0664);         /* 4: group-writable */
    dir("bad/.gnupg", 0700);                              /*    fine */
    file("bad/.netrc", "x", 0640);                        /* 5: readable by group */
    dir("bad/.aws", 0755);
    file("bad/.aws/credentials", "x", 0600);             /*    fine */
    CHECK(gaudit_private_files_check(at("bad"), me, NOGRP, first, sizeof first) == 5);
    CHECK(strcmp(first, "~/.ssh") == 0);

    /* GnuPG: a private folder can still hold a readable key. */
    dir("gpg", 0750);
    dir("gpg/.gnupg", 0700);                              /*    fine */
    dir("gpg/.gnupg/private-keys-v1.d", 0755);            /* 1: folder open */
    file("gpg/.gnupg/private-keys-v1.d/ABCDEF.key", "x", 0644);  /* 2: key readable */
    file("gpg/.gnupg/private-keys-v1.d/123456.key", "x", 0600);  /*    fine */
    file("gpg/.gnupg/secring.gpg", "x", 0644);            /* 3: GnuPG 1 secret keyring */
    file("gpg/.gnupg/pubring.kbx", "x", 0644);            /*    fine */
    CHECK(gaudit_private_files_check(at("gpg"), me, NOGRP, first, sizeof first) == 3);
    CHECK(strcmp(first, "~/.gnupg/private-keys-v1.d") == 0);

    /* The user's own private group counts as the owner for secrets judged
     * by reach (Ubuntu's umask 002 makes many files 0664), but not for the
     * modes ssh and gpg insist on. */
    dir("own", 0750);
    file("own/.netrc", "x", 0640);
    dir("own/.ssh", 0750);
    CHECK(gaudit_private_files_check(at("own"), me, NOGRP, first, sizeof first) == 2);
    CHECK(gaudit_private_files_check(at("own"), me, getgid(), first, sizeof first) == 1);
    CHECK(strcmp(first, "~/.ssh") == 0);

    /* Browser profiles: a closed profile folder protects readable files. */
    dir("web", 0755);
    dir("web/.mozilla", 0755);
    dir("web/.mozilla/firefox", 0755);
    dir("web/.mozilla/firefox/ab12.default", 0700);
    file("web/.mozilla/firefox/ab12.default/logins.json", "{}", 0664);   /*    fine */
    dir("web/.mozilla/firefox/cd34.old", 0755);
    file("web/.mozilla/firefox/cd34.old/key4.db", "x", 0644);            /* 1 */
    dir("web/.var", 0755);
    dir("web/.var/app", 0755);
    dir("web/.var/app/org.chromium.Chromium", 0755);
    dir("web/.var/app/org.chromium.Chromium/config", 0755);
    dir("web/.var/app/org.chromium.Chromium/config/chromium", 0755);
    dir("web/.var/app/org.chromium.Chromium/config/chromium/Default", 0755);
    file("web/.var/app/org.chromium.Chromium/config/chromium/Default/Login Data", "x", 0644); /* 2 */
    dir("web/.password-store", 0755);                                    /* 3: listing */
    file("web/.password-store/bank.gpg", "x", 0600);                     /*    fine */
    CHECK(gaudit_private_files_check(at("web"), me, NOGRP, first, sizeof first) == 3);

    /* A home with glob characters in its name stays literal. */
    dir("we[b]*", 0755);
    dir("we[b]*/.pki", 0755);
    dir("we[b]*/.pki/nssdb", 0755);
    file("we[b]*/.pki/nssdb/key4.db", "x", 0644);
    CHECK(gaudit_private_files_check(at("we[b]*"), me, NOGRP, first, sizeof first) == 1);
    CHECK(strcmp(first, "~/.pki/nssdb/key4.db") == 0);

    /* The home directory itself writable by others undoes the rest. */
    dir("open-home", 0777);
    CHECK(gaudit_private_files_check(at("open-home"), me, NOGRP, first, sizeof first) == 1);
    CHECK(strcmp(first, "~/") == 0);

    /* Owned by someone else (here: we pretend to be another uid). */
    CHECK(gaudit_private_files_check(at("good"), me + 1, NOGRP, first, sizeof first) >= 1);

    /* A symlinked secret is judged by its target. */
    dir("link", 0750);
    file("link/real-netrc", "x", 0644);
    char target[2048], linkpath[2048];
    snprintf(target, sizeof target, "%s/real-netrc", at("link"));
    snprintf(linkpath, sizeof linkpath, "%s/.netrc", at("link"));
    CHECK(symlink(target, linkpath) == 0);
    CHECK(gaudit_private_files_check(at("link"), me, NOGRP, first, sizeof first) == 1);
    CHECK(strcmp(first, "~/.netrc") == 0);

    /* Nothing to look at. */
    CHECK(gaudit_private_files_check(at("missing"), me, NOGRP, first, sizeof first) == -1);
    CHECK(gaudit_private_files_check("relative/path", me, NOGRP, first, sizeof first) == -1);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s)\n", failures, base);
    else
        nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS);  /* kept on failure, to look at */
    return failures ? 1 : 0;
}
