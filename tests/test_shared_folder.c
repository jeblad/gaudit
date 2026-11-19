/* SPDX-License-Identifier: GPL-3.0-only */
/* Shared Folder: its line format round-trips and refuses what it should,
 * and the collection, on a home folder the test builds (never the real
 * one), gives lines the GUI accepts: the folder in use, a duplicate, and
 * the services from a smb.conf and usershares of the test's own. */
#define _GNU_SOURCE
#include "shared-folder.h"
#include "shared-mode.h"

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

static void put(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

int main(void)
{
    /* Round trips, with a name in UTF-8 and a quote. */
    char buf[2048];
    gaudit_shared_folder f = { .lang = "de", .current = 1, .entries = 12 }, f2;
    snprintf(f.name, sizeof f.name, "Öffentlich \"x\"");
    CHECK(gaudit_shared_format_folder(&f, buf, sizeof buf) == 0);
    CHECK(gaudit_shared_parse_line(buf, NULL, &f2, NULL, NULL) == GAUDIT_SHARED_LINE_FOLDER
          && strcmp(f2.name, f.name) == 0 && f2.entries == 12 && f2.current == 1);
    gaudit_shared_config c = { .state = 1, .standard = "~/Offentlig", .exists = 1, .locale = "nb_NO" }, c2;
    CHECK(gaudit_shared_format_config(&c, buf, sizeof buf) == 0
          && gaudit_shared_parse_line(buf, &c2, NULL, NULL, NULL) == GAUDIT_SHARED_LINE_CONFIG
          && strcmp(c2.standard, "~/Offentlig") == 0);
    gaudit_shared_service s = { .kind = "samba-user", .name = "Bilder", .path = "/home/u/Bilder" }, s2;
    CHECK(gaudit_shared_format_service(&s, buf, sizeof buf) == 0
          && gaudit_shared_parse_line(buf, NULL, NULL, &s2, NULL) == GAUDIT_SHARED_LINE_SERVICE
          && strcmp(s2.path, s.path) == 0);
    /* Refused: a name with a folder in it, an unknown kind, a relative
     * share, a standard that is neither ~/ nor absolute. */
    CHECK(gaudit_shared_parse_line("(shared-folder (name \"a/b\") (lang \"\") (machine 0) (current 0)"
                                   " (standard 0) (link 0) (target \"\") (case 0) (entries 0))",
                                   NULL, NULL, NULL, NULL) == -1);
    CHECK(gaudit_shared_parse_line("(shared-folder (name \"..\") (lang \"\") (machine 0) (current 0)"
                                   " (standard 0) (link 0) (target \"\") (case 0) (entries 0))",
                                   NULL, NULL, NULL, NULL) == -1);
    CHECK(gaudit_shared_parse_line("(shared-service (kind \"ftp\") (name \"x\") (path \"/x\"))",
                                   NULL, NULL, NULL, NULL) == -1);
    CHECK(gaudit_shared_parse_line("(shared-service (kind \"samba\") (name \"x\") (path \"x\"))",
                                   NULL, NULL, NULL, NULL) == -1);
    CHECK(gaudit_shared_parse_line("(shared-config (state 1) (standard \"Public\") (exists 1) (locale \"\")"
                                   " (default \"\") (names 1))", NULL, NULL, NULL, NULL) == -1);
    char clash[256];
    gaudit_shared_moves m;
    CHECK(gaudit_shared_parse_tidy("(shared-clash (name \"a.txt\"))", clash, sizeof clash, &m) == 1
          && strcmp(clash, "a.txt") == 0);
    CHECK(gaudit_shared_parse_tidy("(shared-moves (result 1) (moved 2) (clashes 1) (other-disk 0) (failed 0))",
                                   clash, sizeof clash, &m) == 2 && m.result == 1 && m.moved == 2);
    CHECK(gaudit_shared_parse_tidy("(shared-removed (result 3))", clash, sizeof clash, &m) == -1);

    /* The collection on a home folder of the test's own. */
    char dir[] = "/tmp/gaudit-shared-XXXXXX";
    if (mkdtemp(dir) == NULL)
        return 1;
    char p[2600], conf[1200], us[1200], proc[1200], locales[1200];
    const char *mk[] = { "Offentlig", "Public", ".config", "usershares", "proc", "locale" };
    for (size_t i = 0; i < sizeof mk / sizeof mk[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, mk[i]);
        mkdir(p, 0755);
    }
    snprintf(p, sizeof p, "%s/Public/note.txt", dir);
    put(p, "x");
    snprintf(p, sizeof p, "%s/.config/user-dirs.dirs", dir);
    put(p, "XDG_PUBLICSHARE_DIR=\"$HOME/Offentlig\"\n");
    snprintf(us, sizeof us, "%s/usershares", dir);
    snprintf(conf, sizeof conf, "%s/smb.conf", dir);
    char text[1600];
    snprintf(text, sizeof text, "[global]\n  usershare path = %s\n[printers]\n path = /var/spool\n"
                                "[media]\n Path = /srv/media\n", us);
    put(conf, text);
    snprintf(p, sizeof p, "%s/bilder", us);
    snprintf(text, sizeof text, "#VERSION 2\npath=%s/Public\ncomment=\nsharename=Bilder\n", dir);
    put(p, text);
    snprintf(proc, sizeof proc, "%s/proc", dir);
    snprintf(locales, sizeof locales, "%s/locale", dir);
    const char *ld[] = { locales, NULL };

    char *out = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&out, &len);
    CHECK(gaudit_shared_collect(dir, (unsigned)getuid(), ld, conf, proc, mem) == 0);
    fclose(mem);
    int config = 0, folders = 0, standard = 0, services = 0, end = 0, bad = 0;
    for (char *line = strtok(out, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        gaudit_shared_folder ff;
        gaudit_shared_service ss;
        gaudit_shared_end ee;
        gaudit_shared_config cc;
        switch (gaudit_shared_parse_line(line, &cc, &ff, &ss, &ee)) {
        case GAUDIT_SHARED_LINE_CONFIG: config += cc.state == 1 && strcmp(cc.standard, "~/Offentlig") == 0; break;
        case GAUDIT_SHARED_LINE_FOLDER: folders++; standard += ff.standard; break;
        case GAUDIT_SHARED_LINE_SERVICE: services++; break;
        case GAUDIT_SHARED_LINE_END: end += ee.folders == 2 && ee.services == 2; break;
        default: fprintf(stderr, "refused: %s\n", line); bad++;
        }
    }
    free(out);
    /* Offentlig and Public; the usershare and [media] (not [printers]). */
    CHECK(config == 1 && folders == 2 && standard == 1 && services == 2 && end == 1 && bad == 0);

    snprintf(p, sizeof p, "rm -rf -- '%s'", dir);
    if (system(p) != 0)
        failures++;
    if (failures == 0)
        puts("shared-folder: all checks passed");
    return failures == 0 ? 0 : 1;
}
