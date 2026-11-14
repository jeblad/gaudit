/* SPDX-License-Identifier: GPL-3.0-only */
/* Private Files has one collection: everything the known-locations check
 * (Home's count) finds must be in the full list (page 2), once, and the
 * deep scan adds what lies elsewhere. Runs on a home built here, never the
 * real one. */
#include "private-files.h"
#include "secrets-mode.h"
#include "secrets.h"

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

static char base[] = "/tmp/gaudit-collect-XXXXXX";

static void put(const char *rel, const char *content, mode_t mode)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    for (char *p = path + strlen(base) + 1; *p != '\0'; p++)
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        perror(path);
        exit(1);
    }
    fputs(content, fp);
    fclose(fp);
    chmod(path, mode);
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

typedef struct {
    char paths[16][256];
    int n;
} known;

static void on_known(const char *rel, gaudit_private_rule rule, void *ctx)
{
    (void)rule;
    known *k = ctx;
    if (k->n < 16)
        snprintf(k->paths[k->n++], sizeof k->paths[0], "%s", rel[0] != '\0' ? rel : ".");
}

int main(void)
{
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    chmod(base, 0755);
    static const char key[] =
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "-----END OPENSSH PRIVATE KEY-----\n";
    put(".netrc", "machine example.org login me password x\n", 0644);  /* known, others */
    put(".ssh/id_ed25519", key, 0600);
    char ssh[512];
    snprintf(ssh, sizeof ssh, "%s/.ssh", base);
    chmod(ssh, 0755);                                                  /* known: ssh refuses */
    put("Desktop/copy.key", key, 0644);                                /* deep scan only */
    put("Documents/notes.txt", "nothing secret here\n", 0644);

    /* The known locations, as Home counts them. */
    known k = { .n = 0 };
    int problems = gaudit_private_files_each(base, getuid(), (gid_t)-1, on_known, &k);
    CHECK(problems == k.n && problems >= 2);

    /* The full collection, as page 2 gets it. */
    struct passwd pw = { .pw_name = (char *)"nobody-here", .pw_dir = base,
                         .pw_uid = getuid(), .pw_gid = (gid_t)-2 };
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    CHECK(out != NULL && gaudit_private_files_collect(&pw, out) == 0);
    fclose(out);

    gaudit_secret_finding f[64];
    int n = 0;
    gaudit_secrets_summary sum = { 0 };
    int have_sum = 0;
    for (char *line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        gaudit_secret_finding one;
        int r = gaudit_secrets_parse_line(line, &one, &sum);
        CHECK(r == 1 || r == 2);
        if (r == 1 && n < 64)
            f[n++] = one;
        if (r == 2)
            have_sum = 1;
    }
    free(buf);
    CHECK(have_sum && sum.status == GAUDIT_SECRETS_OK && (int)sum.shown == n);

    /* Home's findings are all there, each once. */
    for (int i = 0; i < k.n; i++) {
        int times = 0;
        for (int j = 0; j < n; j++)
            times += strcmp(f[j].path, k.paths[i]) == 0;
        if (times != 1) {
            fprintf(stderr, "known finding %s listed %d times\n", k.paths[i], times);
            failures++;
        }
    }
    /* And the deep scan adds the stray key. */
    int stray = 0;
    for (int j = 0; j < n; j++)
        stray += strcmp(f[j].path, "Desktop/copy.key") == 0;
    CHECK(stray == 1);
    CHECK(gaudit_secrets_verdict(&sum) == GAUDIT_VERDICT_WARNING);

    nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    if (failures == 0)
        puts("secrets-collect: all checks passed");
    return failures == 0 ? 0 : 1;
}
