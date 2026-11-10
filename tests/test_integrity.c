/* SPDX-License-Identifier: GPL-3.0-only */
/* MD5 against RFC 1321's test suite, and the package integrity scan on a
 * small tree built here: unchanged, changed, replaced by a symbolic link,
 * missing, missing but kept out by path-exclude, diverted, unreadable and
 * malformed lines. Never reads the real dpkg database. */
#include "integrity.h"
#include "md5.h"

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

static void md5_of(const char *data, size_t len, char hex[33])
{
    gaudit_md5 m;
    unsigned char d[16];
    gaudit_md5_init(&m);
    gaudit_md5_update(&m, data, len);
    gaudit_md5_final(&m, d);
    gaudit_md5_hex(d, hex);
}

static void test_md5(void)
{
    static const struct { const char *in, *out; } v[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "a", "0cc175b9c0f1b6a831c399e269772661" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "d174ab98d277d9f5a5611c2c9f419d9f" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
          "57edf4a22be3c955ac49da2e2107b67a" },
    };
    char hex[33];
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        md5_of(v[i].in, strlen(v[i].in), hex);
        CHECK(strcmp(hex, v[i].out) == 0);
    }

    /* A million "a" in uneven pieces: every path through update. */
    gaudit_md5 m;
    unsigned char d[16];
    char chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    gaudit_md5_init(&m);
    size_t left = 1000000, step = 1;
    while (left > 0) {
        size_t n = step < left ? step : left;
        gaudit_md5_update(&m, chunk, n);
        left -= n;
        step = step % 997 + 1;
    }
    gaudit_md5_final(&m, d);
    gaudit_md5_hex(d, hex);
    CHECK(strcmp(hex, "7707d6ae4e027c70eea2a935c2296f21") == 0);
}

static char base[] = "/tmp/gaudit-integrity-XXXXXX";

static void put(const char *rel, const char *content)
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
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    chmod(path, 0700);
    return remove(path);
}

typedef struct {
    unsigned kinds[GAUDIT_INTEGRITY_KINDS];
    char changed[8][128];
    unsigned n_changed;
} seen;

static void on_finding(gaudit_integrity_kind kind, const char *package, const char *path, void *ctx)
{
    seen *s = ctx;
    s->kinds[kind]++;
    if (kind == GAUDIT_INTEGRITY_CHANGED && s->n_changed < 8)
        snprintf(s->changed[s->n_changed++], sizeof s->changed[0], "%s %s", package, path);
}

static int has_changed(const seen *s, const char *what)
{
    for (unsigned i = 0; i < s->n_changed; i++)
        if (strcmp(s->changed[i], what) == 0)
            return 1;
    return 0;
}

static void test_scan(void)
{
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    /* md5("hello\n") = b1946ac92492d2347c6235b4d2611184 */
    const char *hello = "b1946ac92492d2347c6235b4d2611184";
    char list[2048];

    put("root/usr/bin/good", "hello\n");
    put("root/usr/bin/changed", "evil\n");
    put("root/usr/bin/target", "hello\n");
    put("root/usr/share/doc/a/README", "hello\n");
    char link[512], target[512];
    snprintf(link, sizeof link, "%s/root/usr/bin/link", base);
    snprintf(target, sizeof target, "%s/root/usr/bin/target", base);
    CHECK(symlink(target, link) == 0);
    put("root/usr/lib/secret", "hello\n");
    char secret[512];
    snprintf(secret, sizeof secret, "%s/root/usr/lib/secret", base);
    chmod(secret, 0);

    snprintf(list, sizeof list,
             "%s  usr/bin/good\n"
             "%s  usr/bin/changed\n"
             "%s  usr/bin/link\n"
             "%s  usr/share/doc/a/README\n"
             "%s  usr/share/doc/a/changelog.gz\n"   /* missing, excluded */
             "%s  usr/share/doc/a/copyright\n"      /* missing, included again */
             "%s  usr/bin/diverted\n"               /* missing, but diverted */
             "zz34567890123456789012345678901  usr/bin/bad\n"
             "%s  usr/../etc/shadow\n"
             "\n",
             hello, hello, hello, hello, hello, hello, hello, hello);
    put("info/a.md5sums", list);
    snprintf(list, sizeof list, "%s  usr/lib/secret\n%s  usr/lib/gone\n", hello, hello);
    put("info/b:amd64.md5sums", list);
    put("info/b:amd64.list", "not an md5sums file\n");
    put("diversions", "/usr/bin/diverted\n/usr/bin/diverted.real\nother\n");
    put("dpkg.cfg.d/excludes", "# docs\npath-exclude=/usr/share/doc/*\npath-include /usr/share/doc/*/copyright\n");
    put("dpkg.cfg.d/ignored.conf", "path-include=/usr/share/doc/*\n");  /* not a fragment name */

    char root[512], info[512], div[512], cfgd[512], cfg[512];
    snprintf(root, sizeof root, "%s/root", base);
    snprintf(info, sizeof info, "%s/info", base);
    snprintf(div, sizeof div, "%s/diversions", base);
    snprintf(cfgd, sizeof cfgd, "%s/dpkg.cfg.d", base);
    snprintf(cfg, sizeof cfg, "%s/dpkg.cfg", base);  /* absent */

    for (unsigned threads = 1; threads <= 4; threads += 3) {
        gaudit_integrity_paths p = { .root = root, .info_dir = info, .diversions = div,
                                     .cfg_file = cfg, .cfg_dir = cfgd, .threads = threads };
        gaudit_integrity_result r;
        seen s;
        memset(&s, 0, sizeof s);
        CHECK(gaudit_integrity_scan(&p, &r, on_finding, &s) == 0);
        CHECK(r.packages == 2);
        CHECK(r.files == 9);           /* every well-formed line */
        CHECK(r.bad_lines == 2);
        CHECK(r.diverted == 1);
        CHECK(r.excluded == 1);
        CHECK(r.changed == 2);         /* changed content, and a symbolic link */
        CHECK(has_changed(&s, "a /usr/bin/changed"));
        CHECK(has_changed(&s, "a /usr/bin/link"));
        CHECK(r.missing == 2);         /* copyright (included again) and gone */
        CHECK(s.kinds[GAUDIT_INTEGRITY_MISSING] == 2);
        if (geteuid() != 0) {
            CHECK(r.unreadable == 1);
            CHECK(r.checked == 4);     /* good, changed, link, README */
        } else {
            CHECK(r.unreadable == 0);  /* root reads it anyway */
            CHECK(r.checked == 5);
        }
        /* good 6, changed 5, README 6 (+ secret 6 as root); the link is never read */
        CHECK(r.bytes == (geteuid() != 0 ? 17u : 23u));
    }

    /* No database: the scan cannot run. */
    gaudit_integrity_paths none = { .root = root, .info_dir = "/nonexistent/gaudit", .threads = 1 };
    gaudit_integrity_result r;
    CHECK(gaudit_integrity_scan(&none, &r, NULL, NULL) == -1);

    nftw(base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
}

int main(void)
{
    test_md5();
    test_scan();
    if (failures == 0)
        puts("integrity: all checks passed");
    return failures == 0 ? 0 : 1;
}
