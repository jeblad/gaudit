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
    char p[4096], text[2048];
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
    CHECK(gaudit_cloud_collect(home, mounts, root, 0, mem) == 0);
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
    /* The unit: written once, the same again is fine, another file of that
     * name is left alone; a remote name that may not go into a file, a
     * gathering folder or a language not in the table, a disk not known,
     * are refused. */
    char result[16];
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "jotta-crypt",
                                  "Skytjenester", "nb", result, sizeof result) == 0
          && strcmp(result, "written") == 0);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "jotta-crypt",
                                  "Skytjenester", "nb", result, sizeof result) == 0
          && strcmp(result, "unchanged") == 0);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "jotta", "Skytjenester", "nb",
                                  result, sizeof result) == 1
          && strcmp(result, "foreign") == 0);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "shared", "jotta", "Skytjenester", "nb",
                                  result, sizeof result) == 0
          && strcmp(result, "written") == 0);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "a b; rm", "Cloud", "en", result,
                                  sizeof result) == 2
          && strcmp(result, "refused") == 0);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "jotta", "../../tmp", "en", result,
                                  sizeof result) == 2);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "private", "jotta", "Cloud", "xx", result,
                                  sizeof result) == 2);
    CHECK(gaudit_cloud_write_unit(home, "jottacloud", "both", "jotta", "Cloud", "en", result,
                                  sizeof result) == 2);
    CHECK(gaudit_cloud_write_unit(home, "nowhere", "private", "jotta", "Cloud", "en", result,
                                  sizeof result) == 2);
    /* The texts: quoted where the name has spaces, the shareable one
     * without the encrypted folder. */
    {
        const gaudit_cloud_setup_service *sv = gaudit_cloud_setup_find("dropbox");
        char folder[128], unit[4096], uname[96];
        gaudit_cloud_folder_name(sv, GAUDIT_CLOUD_DISK_SHARED, "privat", "delt mappe", folder,
                                 sizeof folder);
        CHECK(strcmp(folder, "Dropbox (delt mappe)") == 0);
        CHECK(gaudit_cloud_unit_text(sv, GAUDIT_CLOUD_DISK_SHARED, "dropbox", "Skytjenester",
                                     folder, unit, sizeof unit) == 0
              && strstr(unit, "rclone mount dropbox: \"%h/Skytjenester/Dropbox (delt mappe)\" "
                              "--umask 077") != NULL
              && strstr(unit, "--exclude /Encrypted/**") != NULL);
        gaudit_cloud_folder_name(sv, GAUDIT_CLOUD_DISK_PRIVATE, "privat", "delt mappe", folder,
                                 sizeof folder);
        CHECK(strcmp(folder, "Dropbox (privat)") == 0);   /* always with its kind */
        CHECK(gaudit_cloud_unit_text(sv, GAUDIT_CLOUD_DISK_PRIVATE, "dropbox-crypt", "Cloud", folder,
                                     unit, sizeof unit) == 0
              && strstr(unit, "--exclude") == NULL
              && strstr(unit, "rclone mount dropbox-crypt: \"%h/Cloud/Dropbox (privat)\"") != NULL);
        CHECK(gaudit_cloud_unit_text(sv, GAUDIT_CLOUD_DISK_PRIVATE, "dropbox", "Cloud", "a\"b", unit,
                                     sizeof unit) == -1);
        gaudit_cloud_unit_name(sv, GAUDIT_CLOUD_DISK_PRIVATE, uname, sizeof uname);
        CHECK(strcmp(uname, "rclone-dropbox-private.service") == 0);
    }
    /* The collection then reports them, not mounted, at the folder with spaces. */
    out = NULL;
    len = 0;
    mem = open_memstream(&out, &len);
    CHECK(gaudit_cloud_collect(home, mounts, root, 0, mem) == 0);
    fclose(mem);
    gaudit_cloud_unit_line ul;
    int units = 0;
    for (char *line = strtok(out, "\n"); line != NULL; line = strtok(NULL, "\n"))
        if (gaudit_cloud_parse_unit(line, &ul) == 3)
            units += (strcmp(ul.file, "rclone-jottacloud-private.service") == 0 && !ul.mounted
                      && strcmp(ul.path, "~/Skytjenester/Jottacloud (privat)") == 0)
                     + (strcmp(ul.file, "rclone-jottacloud-shared.service") == 0
                        && strcmp(ul.path, "~/Skytjenester/Jottacloud (delt mappe)") == 0);
    free(out);
    CHECK(units == 2);

    /* Files outside the encrypted folder: counted by a stand-in for rclone
     * that checks what it is asked and lists names; the encrypted folder's
     * own entry is not counted, no name comes out, and a remote the
     * collection does not find, or one without encryption, is refused. */
    snprintf(p, sizeof p, "mkdir -p -- '%s/home/.config/rclone'", dir);
    CHECK(system(p) == 0);
    snprintf(p, sizeof p, "%s/home/.config/rclone/rclone.conf", dir);
    if ((fp = fopen(p, "w")) != NULL) {
        fputs("[box]\ntype = dropbox\ntoken = SECRET\n\n[box-crypt]\ntype = crypt\n"
              "remote = box:Encrypted\npassword = XXX\n\n[plain]\ntype = dropbox\n", fp);
        fclose(fp);
    }
    char fake[1100], fail[1100];
    snprintf(fake, sizeof fake, "%s/rclone", dir);
    snprintf(fail, sizeof fail, "%s/rclone-fails", dir);
    if ((fp = fopen(fake, "w")) != NULL) {
        fputs("#!/bin/sh\n"
              "[ \"$1 $2 $3 $4 $5 $6\" = 'lsf --max-depth 1 --exclude /Encrypted/** box:' ] || exit 3\n"
              "[ -n \"$HOME\" ] || exit 4\n"
              "printf 'secret-name.txt\\nEncrypted/\\nPhotos/\\n'\n", fp);
        fclose(fp);
    }
    if ((fp = fopen(fail, "w")) != NULL) {
        fputs("#!/bin/sh\nexit 1\n", fp);
        fclose(fp);
    }
    snprintf(p, sizeof p, "chmod 0755 -- '%s' '%s'", fake, fail);
    CHECK(system(p) == 0);
    {
        gaudit_cloud_plain_line pl;
        char *pout = NULL;
        size_t plen = 0;
        FILE *pm = open_memstream(&pout, &plen);
        CHECK(gaudit_cloud_plain(home, mounts, "box", fake, pm) == 0);
        CHECK(gaudit_cloud_plain(home, mounts, "box", fail, pm) == 0);
        CHECK(gaudit_cloud_plain(home, mounts, "plain", fake, pm) == 1);   /* not encrypted */
        CHECK(gaudit_cloud_plain(home, mounts, "nowhere", fake, pm) == 1);
        CHECK(gaudit_cloud_plain(home, mounts, "-x", fake, pm) == 1);
        fclose(pm);
        CHECK(pout != NULL && strstr(pout, "secret-name") == NULL && strstr(pout, "SECRET") == NULL);
        char *second = pout != NULL ? strchr(pout, '\n') : NULL;
        if (second != NULL)
            *second++ = '\0';
        CHECK(pout != NULL && gaudit_cloud_parse_plain(pout, &pl) == 0 && pl.status == 0
              && pl.count == 2 && !pl.more && strcmp(pl.remote, "box") == 0);
        CHECK(second != NULL && gaudit_cloud_parse_plain(second, &pl) == 0 && pl.status == 1
              && pl.count == 0);
        free(pout);
        CHECK(gaudit_cloud_parse_plain("(cloud-plain (remote \"a b\") (status 0) (count 1) (more 0))",
                                       NULL) == -1);
        CHECK(gaudit_cloud_parse_plain("(cloud-plain (remote \"box\") (status 3) (count 1) (more 0))",
                                       NULL) == -1);
    }

    /* Secrets in a cloud folder kept on this computer: only in the full
     * collection, the path shown from home, no content. */
    snprintf(p, sizeof p, "mkdir -p -- '%s/home/Dropbox/keys'", dir);
    CHECK(system(p) == 0);
    snprintf(p, sizeof p, "%s/home/Dropbox/keys/vault.kdbx", dir);
    if ((fp = fopen(p, "w")) != NULL) {
        fputs("not a real database", fp);
        fclose(fp);
    }
    snprintf(p, sizeof p, "%s/home/Dropbox/keys/deploy", dir);
    if ((fp = fopen(p, "w")) != NULL) {
        fputs("-----BEGIN OPENSSH PRIVATE KEY-----\n"
              "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
              "-----END OPENSSH PRIVATE KEY-----\n", fp);
        fclose(fp);
    }
    for (int full = 0; full < 2; full++) {
        char *sout = NULL;
        size_t slen = 0;
        FILE *sm = open_memstream(&sout, &slen);
        CHECK(gaudit_cloud_collect(home, mounts, root, full, sm) == 0);
        fclose(sm);
        int hits = 0, sums = 0, kdbx = 0;
        for (char *line = strtok(sout, "\n"); line != NULL; line = strtok(NULL, "\n")) {
            gaudit_cloud_secret_line sl;
            gaudit_cloud_secret_scan_line ss;
            if (gaudit_cloud_parse_secret(line, &sl) == 0) {
                hits++;
                kdbx += strcmp(sl.path, "~/Dropbox/keys/vault.kdbx") == 0
                        && strcmp(sl.reason, "keepass") == 0 && strcmp(sl.service, "dropbox") == 0;
            } else if (gaudit_cloud_parse_secret_scan(line, &ss) == 0) {
                sums += ss.folders == 1 && ss.found == 2 && !ss.more;
            }
        }
        CHECK(full ? hits == 2 && sums == 1 && kdbx == 1 : hits == 0 && sums == 0);
        CHECK(sout == NULL || strstr(sout, "b3BlbnNzaC1") == NULL);
        free(sout);
    }

    /* Names at a remote that look like secrets, on a click: outside the
     * encrypted folder only, by name; a name known only as a key file's
     * usual name is marked a guess. */
    snprintf(fake, sizeof fake, "%s/rclone-names", dir);
    if ((fp = fopen(fake, "w")) != NULL) {
        fputs("#!/bin/sh\n"
              "[ \"$1 $2 $3 $4 $5 $6\" = 'lsf -R --files-only --exclude /Encrypted/** box:' ] || exit 3\n"
              "printf 'notes.txt\\nold/vault.kdbx\\nssh/id_ed25519\\nssh/id_ed25519.pub\\n'\n", fp);
        fclose(fp);
    }
    snprintf(p, sizeof p, "chmod 0755 -- '%s'", fake);
    CHECK(system(p) == 0);
    {
        char *nout = NULL;
        size_t nlen = 0;
        FILE *nm = open_memstream(&nout, &nlen);
        CHECK(gaudit_cloud_names(home, mounts, "box", fake, nm) == 0);
        CHECK(gaudit_cloud_names(home, mounts, "nowhere", fake, nm) == 1);
        fclose(nm);
        int kdbx = 0, ssh = 0, sums = 0, other = 0;
        for (char *line = strtok(nout, "\n"); line != NULL; line = strtok(NULL, "\n")) {
            gaudit_cloud_secret_line sl;
            gaudit_cloud_names_line nl;
            if (gaudit_cloud_parse_secret(line, &sl) == 0) {
                kdbx += strcmp(sl.path, "old/vault.kdbx") == 0 && !sl.by_name
                        && strcmp(sl.remote, "box") == 0;
                ssh += strcmp(sl.path, "ssh/id_ed25519") == 0 && sl.by_name;
            } else if (gaudit_cloud_parse_names(line, &nl) == 0) {
                sums += nl.status == 0 && nl.looked == 4 && nl.found == 2 && !nl.more;
            } else {
                other++;
            }
        }
        CHECK(kdbx == 1 && ssh == 1 && sums == 1 && other == 0);
        CHECK(nout == NULL || strstr(nout, "notes.txt") == NULL);
        free(nout);
    }

    snprintf(p, sizeof p, "rm -rf -- '%s'", dir);
    if (system(p) != 0)
        failures++;
    if (failures == 0)
        puts("cloud: all checks passed");
    /* The rule's list of services Set Up With rclone knows is the table's,
     * written as (define setup-services '("a" "b")). */
    {
        FILE *r = fopen(CLOUD_RULE, "r");
        static char rule[65536];
        size_t got = r != NULL ? fread(rule, 1, sizeof rule - 1, r) : 0;
        if (r != NULL)
            fclose(r);
        rule[got] = '\0';
        const char *at = strstr(rule, "(define setup-services '(");
        CHECK(at != NULL);
        char list[512] = "";
        if (at != NULL) {
            at += strlen("(define setup-services '(");
            const char *end = strchr(at, ')');
            if (end != NULL && (size_t)(end - at) < sizeof list)
                memcpy(list, at, (size_t)(end - at)), list[end - at] = '\0';
        }
        char want[512] = "";
        for (unsigned i = 0; i < gaudit_cloud_setup_services_count; i++) {
            size_t n = strlen(want);
            snprintf(want + n, sizeof want - n, "%s\"%s\"", i > 0 ? " " : "",
                     gaudit_cloud_setup_services[i].id);
        }
        CHECK(strcmp(list, want) == 0);
    }
    return failures == 0 ? 0 : 1;
}
