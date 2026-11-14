/* SPDX-License-Identifier: GPL-3.0-only */
/* Private Files has one collection at two levels: everything the
 * known-locations check finds is in the quick collection (Home) and in the
 * full one (page 2), once, and the deep scan adds what lies elsewhere. Runs
 * on a home built here, never the real one. */
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

    struct passwd pw = { .pw_name = (char *)"nobody-here", .pw_dir = base,
                         .pw_uid = getuid(), .pw_gid = (gid_t)-2 };
    for (int deep = 0; deep <= 1; deep++) {
        char *buf = NULL;
        size_t len = 0;
        FILE *out = open_memstream(&buf, &len);
        CHECK(out != NULL && gaudit_private_files_collect(&pw, deep, NULL, 0, out) == 0);
        fclose(out);

        gaudit_secret_finding f[64];
        int n = 0;
        gaudit_secrets_summary sum = { 0 };
        int have_sum = 0;
        for (char *line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
            gaudit_secret_finding one;
            int r = gaudit_secrets_parse_line(line, &one, &sum);
            CHECK(r == 1 || r == 2 || r == 3);
            if (r == 1 && n < 64)
                f[n++] = one;
            if (r == 2)
                have_sum = 1;
        }
        free(buf);
        CHECK(have_sum && sum.status == GAUDIT_SECRETS_OK && (int)sum.shown == n);

        /* The known locations' findings are there, each once, at both levels. */
        for (int i = 0; i < k.n; i++) {
            int times = 0;
            for (int j = 0; j < n; j++)
                times += strcmp(f[j].path, k.paths[i]) == 0;
            if (times != 1) {
                fprintf(stderr, "deep %d: known finding %s listed %d times\n", deep, k.paths[i], times);
                failures++;
            }
        }
        /* Only the full collection adds the stray key. */
        int stray = 0;
        for (int j = 0; j < n; j++)
            stray += strcmp(f[j].path, "Desktop/copy.key") == 0;
        CHECK(stray == deep);
        /* quick: exactly the known locations' problems; full also lists
         * the stray key and the SSH key only the user can read. */
        CHECK(deep ? n == k.n + 2 : n == k.n);
    }

    /* A folder the user added, outside the home folder: its whole tree is
     * searched in the full collection, reach judged from "/" down; one
     * overlapping the home folder and one that does not exist are named,
     * not searched. */
    char extra[] = "/tmp/gaudit-area-XXXXXX";
    CHECK(mkdtemp(extra) != NULL);
    chmod(extra, 0755);
    char sub[512], keyfile[600], inside[600];
    snprintf(sub, sizeof sub, "%s/deep/er", extra);
    snprintf(inside, sizeof inside, "%s/inside", base);
    mkdir(inside, 0755);
    char mid[512];
    snprintf(mid, sizeof mid, "%s/deep", extra);
    mkdir(mid, 0755);
    mkdir(sub, 0755);
    snprintf(keyfile, sizeof keyfile, "%s/id.key", sub);
    FILE *kf = fopen(keyfile, "w");
    CHECK(kf != NULL);
    if (kf != NULL) {
        fputs(key, kf);
        fclose(kf);
    }
    chmod(keyfile, 0644);
    const char *folders[] = { extra, inside, "/nonexistent/gaudit" };
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    CHECK(out != NULL && gaudit_private_files_collect(&pw, 1, folders, 3, out) == 0);
    fclose(out);
    int areas = 0, searched = 0, overlaps = 0, unreadable = 0, in_extra = 0;
    for (char *line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        gaudit_secret_area a;
        gaudit_secret_finding one;
        gaudit_secrets_summary sum;
        if (gaudit_secrets_parse_area(line, &a) == 0) {
            areas++;
            searched += a.status == GAUDIT_AREA_SEARCHED;
            overlaps += a.status == GAUDIT_AREA_OVERLAPS;
            unreadable += a.status == GAUDIT_AREA_UNREADABLE;
        } else if (gaudit_secrets_parse_line(line, &one, &sum) == 1 && one.area == 1) {
            in_extra++;
            /* Every folder from "/" down lets others through, and it is 0644. */
            CHECK(strcmp(one.path, "deep/er/id.key") == 0 && one.reach == GAUDIT_SECRET_OTHERS);
        }
    }
    free(buf);
    CHECK(areas == 4 && searched == 2 && overlaps == 1 && unreadable == 1 && in_extra == 1);
    /* A closed folder on the way protects it. */
    chmod(mid, 0700);
    buf = NULL;
    out = open_memstream(&buf, &len);
    const char *only[] = { extra };
    CHECK(out != NULL && gaudit_private_files_collect(&pw, 1, only, 1, out) == 0);
    fclose(out);
    for (char *line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        gaudit_secret_finding one;
        gaudit_secrets_summary sum;
        if (gaudit_secrets_parse_line(line, &one, &sum) == 1 && one.area == 1)
            CHECK(one.reach == GAUDIT_SECRET_OWNER);
    }
    free(buf);
    nftw(extra, rm_one, 16, FTW_DEPTH | FTW_PHYS);

    nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    if (failures == 0)
        puts("secrets-collect: all checks passed");
    return failures == 0 ? 0 : 1;
}
