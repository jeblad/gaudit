/* SPDX-License-Identifier: GPL-3.0-only */
/* Cloud Services: its line format round-trips and refuses what it should,
 * and the collection, on a home folder the test builds (never the real
 * one), gives lines the GUI accepts, folders in the home folder shown as
 * "~/...". */
#define _GNU_SOURCE
#include "cloud-mode.h"
#include "cloud.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(void)
{
    char buf[2048];
    gaudit_cloud_line f = { .client = "rclone", .service = "google-drive", .how = 4,
                            .name = "g\"drive", .encrypted = 1 }, f2;
    CHECK(gaudit_cloud_format_folder(&f, buf, sizeof buf) == 0
          && gaudit_cloud_parse_line(buf, &f2, NULL) == 1 && strcmp(f2.name, f.name) == 0
          && f2.encrypted == 1 && f2.how == 4);
    gaudit_cloud_end e = { .count = 1, .gathering = "~/Cloud", .gatherings = 1 }, e2;
    CHECK(gaudit_cloud_format_end(&e, buf, sizeof buf) == 0
          && gaudit_cloud_parse_line(buf, NULL, &e2) == 2 && strcmp(e2.gathering, "~/Cloud") == 0);
    /* Refused: an id with other characters, a relative path, a how out of range. */
    CHECK(gaudit_cloud_parse_line("(cloud-folder (client \"Drop box\") (service \"dropbox\") (how 0)"
                                  " (path \"\") (name \"\") (encrypted 0) (gathered 0))", NULL, NULL) == -1);
    CHECK(gaudit_cloud_parse_line("(cloud-folder (client \"dropbox\") (service \"dropbox\") (how 0)"
                                  " (path \"Dropbox\") (name \"\") (encrypted 0) (gathered 0))", NULL, NULL) == -1);
    CHECK(gaudit_cloud_parse_line("(cloud-folder (client \"dropbox\") (service \"dropbox\") (how 5)"
                                  " (path \"\") (name \"\") (encrypted 0) (gathered 0))", NULL, NULL) == -1);

    /* The collection on a home of the test's own: Dropbox's folder shown as ~/. */
    char dir[] = "/tmp/gaudit-cloudc-XXXXXX";
    if (mkdtemp(dir) == NULL)
        return 1;
    char p[2048], text[2048];
    snprintf(p, sizeof p, "mkdir -p -- '%s/home/.dropbox' '%s/home/Dropbox' '%s/root'", dir, dir, dir);
    CHECK(system(p) == 0);
    snprintf(p, sizeof p, "%s/home/.dropbox/info.json", dir);
    FILE *fp = fopen(p, "w");
    if (fp != NULL) {
        fprintf(fp, "{\"personal\": {\"path\": \"%s/home/Dropbox\"}}", dir);
        fclose(fp);
    }
    char home[1024], mounts[1024], root[1024];
    snprintf(home, sizeof home, "%s/home", dir);
    snprintf(mounts, sizeof mounts, "%s/none", dir);
    snprintf(root, sizeof root, "%s/root", dir);
    char *out = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&out, &len);
    CHECK(gaudit_cloud_collect(home, mounts, root, mem) == 0);
    fclose(mem);
    snprintf(text, sizeof text, "%s", out != NULL ? out : "");
    free(out);
    int folders = 0, ends = 0, bad = 0;
    for (char *line = strtok(text, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        gaudit_cloud_line l;
        gaudit_cloud_end ee;
        int k = gaudit_cloud_parse_line(line, &l, &ee);
        if (k == 1)
            folders += strcmp(l.path, "~/Dropbox") == 0;
        else if (k == 2)
            ends += ee.count == 1;
        else
            bad++;
    }
    CHECK(folders == 1 && ends == 1 && bad == 0);
    snprintf(p, sizeof p, "rm -rf -- '%s'", dir);
    if (system(p) != 0)
        failures++;
    if (failures == 0)
        puts("cloud: all checks passed");
    return failures == 0 ? 0 : 1;
}
