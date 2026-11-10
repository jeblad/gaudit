/* SPDX-License-Identifier: GPL-3.0-only */
/* The secret scan, on a tree built at run time under the build directory.
 * Never looks at the real home. */
#include "secret-scan.h"

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

#define MAX_HITS 64
static struct { char rel[256]; char reason[32]; gaudit_reach reach; } hits[MAX_HITS];
static int n_hits;

static void collect(const gaudit_secret_hit *hit, void *ctx)
{
    (void)ctx;
    if (n_hits < MAX_HITS) {
        snprintf(hits[n_hits].rel, sizeof hits[n_hits].rel, "%s", hit->rel);
        snprintf(hits[n_hits].reason, sizeof hits[n_hits].reason, "%s", hit->reason);
        hits[n_hits].reach = hit->reach;
    }
    n_hits++;
}

/* The hit for rel, or NULL. */
static const char *reason_of(const char *rel, gaudit_reach *reach)
{
    for (int i = 0; i < n_hits && i < MAX_HITS; i++)
        if (strcmp(hits[i].rel, rel) == 0) {
            if (reach != NULL)
                *reach = hits[i].reach;
            return hits[i].reason;
        }
    return NULL;
}

static int is(const char *rel, const char *reason, gaudit_reach want)
{
    gaudit_reach reach;
    const char *r = reason_of(rel, &reach);
    if (r == NULL || strcmp(r, reason) != 0 || reach != want) {
        fprintf(stderr, "  %s: got %s/%d, want %s/%d\n", rel, r ? r : "(none)",
                r ? (int)reach : -1, reason, (int)want);
        return 0;
    }
    return 1;
}

#define B64 "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
#define PEM "-----BEGIN RSA PRIVATE KEY-----\n" B64 "-----END RSA PRIVATE KEY-----\n"

int main(void)
{
    snprintf(base, sizeof base, "%s/secret-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    chmod(base, 0755);  /* the home itself: open to others */

    /* By content, in odd places. */
    dir("Downloads", 0755);
    file("Downloads/server.key", PEM, 0644);                       /* others */
    file("Downloads/notes.txt", "nothing here\n", 0644);
    dir("work", 0750);
    file("work/deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\n" B64
         "-----END OPENSSH PRIVATE KEY-----\n", 0640);                                 /* group */
    file("work/backup.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: x\n\n" B64
         "-----END PGP PRIVATE KEY BLOCK-----\n", 0600);                                /* owner */
    file("work/enc.pem", "-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\n"
         "DEK-Info: AES-128-CBC,00\r\n\r\n" B64 "-----END RSA PRIVATE KEY-----\r\n", 0600);
    file("work/vpn.ovpn", "client\n<key>\n-----BEGIN PRIVATE KEY-----\n" B64
         "-----END PRIVATE KEY-----\n</key>\n", 0644);
    file("work/putty.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\n", 0644);
    /* Mentions of the markers are not keys. */
    file("work/talk", "the string PRIVATE KEY----- alone is not a key\n", 0644);
    file("work/code", "m = b\"-----BEGIN OPENSSH PRIVATE KEY-----\\n\"\n", 0644);
    file("work/doc", "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n", 0644);
    file("work/half", "-----BEGIN EC PRIVATE KEY-----\n" B64, 0644);  /* no END line */
    file("work/key.py", PEM, 0644);  /* source code is not read */

    /* By name. */
    file("passwords.kdbx", "\x03\xd9\xa2\x9a", 0644);
    file(".netrc", "machine x login y password z\n", 0600);
    dir(".aws", 0700);
    file(".aws/credentials", "[default]\n", 0644);  /* readable file, but .aws is closed */

    /* A readable file behind a closed folder is out of reach. */
    dir("private", 0700);
    file("private/old.pem", PEM, 0644);

    /* Noise folders are skipped, Trash is not. */
    dir(".cache", 0755);
    file(".cache/key.pem", PEM, 0644);
    dir("proj", 0755);
    dir("proj/.git", 0755);
    file("proj/.git/key.pem", PEM, 0644);
    dir(".local", 0755);
    dir(".local/share", 0755);
    dir(".local/share/Trash", 0700);
    dir(".local/share/Trash/files", 0700);
    file(".local/share/Trash/files/id_rsa", PEM, 0600);

    /* Symlinks are never followed. */
    char target[2048], link[2048];
    snprintf(target, sizeof target, "%s/Downloads", base);
    snprintf(link, sizeof link, "%s/loop", base);
    CHECK(symlink(target, link) == 0);
    snprintf(target, sizeof target, "%s/Downloads/server.key", base);
    snprintf(link, sizeof link, "%s/linked.key", base);
    CHECK(symlink(target, link) == 0);

    gaudit_secret_stats st;
    CHECK(gaudit_secret_scan(base, getuid(), collect, NULL, &st) == 0);

    CHECK(is("Downloads/server.key", "pem-private-key", GAUDIT_REACH_OTHERS));
    CHECK(is("work/deploy", "openssh-private-key", GAUDIT_REACH_GROUP));
    CHECK(is("work/backup.asc", "pgp-private-key", GAUDIT_REACH_OWNER));
    CHECK(is("work/vpn.ovpn", "pem-private-key", GAUDIT_REACH_GROUP));  /* work is 0750 */
    CHECK(is("work/enc.pem", "pem-private-key", GAUDIT_REACH_OWNER));
    CHECK(is("work/putty.ppk", "putty-private-key", GAUDIT_REACH_GROUP));
    CHECK(is("passwords.kdbx", "keepass", GAUDIT_REACH_OTHERS));
    CHECK(is(".netrc", "netrc", GAUDIT_REACH_OWNER));
    CHECK(is(".aws/credentials", "aws-credentials", GAUDIT_REACH_OWNER));
    CHECK(is("private/old.pem", "pem-private-key", GAUDIT_REACH_OWNER));
    CHECK(is(".local/share/Trash/files/id_rsa", "pem-private-key", GAUDIT_REACH_OWNER));

    CHECK(reason_of("Downloads/notes.txt", NULL) == NULL);
    CHECK(reason_of("work/talk", NULL) == NULL);
    CHECK(reason_of("work/code", NULL) == NULL);
    CHECK(reason_of("work/doc", NULL) == NULL);
    CHECK(reason_of("work/half", NULL) == NULL);
    CHECK(reason_of("work/key.py", NULL) == NULL);
    CHECK(reason_of(".cache/key.pem", NULL) == NULL);
    CHECK(reason_of("proj/.git/key.pem", NULL) == NULL);
    CHECK(reason_of("loop/server.key", NULL) == NULL);
    CHECK(reason_of("linked.key", NULL) == NULL);
    CHECK(n_hits == 11);
    CHECK(st.skipped == 2);  /* .cache and proj/.git */
    CHECK(!st.truncated);

    CHECK(gaudit_secret_scan("relative", getuid(), collect, NULL, &st) == -1);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s, %d hits)\n", failures, base, n_hits);
    else
        nftw(base, remove_entry, 16, FTW_DEPTH | FTW_PHYS);  /* kept on failure, to look at */
    return failures ? 1 : 0;
}
