/* SPDX-License-Identifier: GPL-3.0-only */
/* dpkg version ordering and the installed-vs-available scan on fixtures in
 * tests/data/dpkg/. */
#include "dpkg.h"

#include "compressed.h"

#include <dirent.h>
#include <lz4frame.h>
#include <lzma.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>
#include <zstd.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define LESS(a, b)  CHECK(gaudit_deb_version_compare(a, b) < 0 && gaudit_deb_version_compare(b, a) > 0)
#define EQUAL(a, b) CHECK(gaudit_deb_version_compare(a, b) == 0)

#define DATA GAUDIT_TEST_DATA_DIR "/dpkg"

static void count_reported(const char *name, const char *arch, const char *version, void *ctx)
{
    (void)arch;
    (void)version;
    CHECK(strcmp(name, "c") == 0 || strcmp(name, "h") == 0 || strcmp(name, "thunderbird") == 0);
    (*(unsigned *)ctx)++;
}

/* --- Compressed indexes, built at run time from the plain fixtures ------- */

static char tmp_dir[1024];

static int read_file(const char *path, char **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = malloc((size_t)n + 1);
    *len = fread(*data, 1, (size_t)n, f);
    fclose(f);
    return *len == (size_t)n ? 0 : -1;
}

static void write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL || fwrite(data, 1, len, f) != len) {
        perror(path);
        exit(1);
    }
    fclose(f);
}

/* A lists directory where every *_Packages file is compressed with fmt
 * ("gz", "xz", "lz4", "zst", or "bz2" for a fake, unsupported one); the
 * InRelease files are copied as they are. truncate: cut the data short. */
static const char *make_lists(const char *fmt, int truncate)
{
    static char dir[1100];
    snprintf(dir, sizeof dir, "%s/lists-%s%s", tmp_dir, fmt, truncate ? "-cut" : "");
    mkdir(dir, 0755);

    DIR *src = opendir(DATA "/lists");
    struct dirent *de;
    while ((de = readdir(src)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char in[1400], out[1400];
        snprintf(in, sizeof in, "%s/%s", DATA "/lists", de->d_name);
        char *data;
        size_t len;
        if (read_file(in, &data, &len) != 0)
            continue;
        if (strstr(de->d_name, "_Packages") == NULL) {
            snprintf(out, sizeof out, "%s/%s", dir, de->d_name);
            write_file(out, data, len);
            free(data);
            continue;
        }
        snprintf(out, sizeof out, "%s/%s.%s", dir, de->d_name, fmt);
        size_t cap = len + 1024, n = 0;
        unsigned char *buf = malloc(cap);
        if (strcmp(fmt, "gz") == 0) {
            gzFile gz = gzopen(out, "wb");
            gzwrite(gz, data, (unsigned)len);
            gzclose(gz);
            if (truncate) {  /* rewrite without the last bytes */
                char *gzdata;
                size_t gzlen;
                read_file(out, &gzdata, &gzlen);
                write_file(out, gzdata, gzlen / 2);
                free(gzdata);
            }
            free(buf);
            free(data);
            continue;
        } else if (strcmp(fmt, "xz") == 0) {
            lzma_easy_buffer_encode(6, LZMA_CHECK_CRC64, NULL, (const uint8_t *)data, len, buf, &n, cap);
        } else if (strcmp(fmt, "lz4") == 0) {
            n = LZ4F_compressFrame(buf, cap, data, len, NULL);
        } else if (strcmp(fmt, "zst") == 0) {
            n = ZSTD_compress(buf, cap, data, len, 3);
        } else {
            memcpy(buf, data, len);  /* "bz2": not actually compressed; never read */
            n = len;
        }
        write_file(out, buf, truncate ? n / 2 : n);
        free(buf);
        free(data);
    }
    closedir(src);
    return dir;
}

static void compressed_cases(void)
{
    snprintf(tmp_dir, sizeof tmp_dir, "%s/dpkg-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(tmp_dir) == NULL) {
        perror("mkdtemp");
        failures++;
        return;
    }

    static const char *const formats[] = { "gz", "xz", "lz4", "zst" };
    for (size_t i = 0; i < sizeof formats / sizeof formats[0]; i++) {
        gaudit_deb_counts c = { 99, 99 };
        gaudit_backend_status st = gaudit_deb_scan(DATA "/status", make_lists(formats[i], 0),
                                                   NULL, NULL, &c);
        if (st != GAUDIT_BACKEND_OK || c.upgradable != 3 || c.obsolete != 2)
            fprintf(stderr, "%s: status %d, upgradable %u, obsolete %u\n",
                    formats[i], (int)st, c.upgradable, c.obsolete);
        CHECK(st == GAUDIT_BACKEND_OK);
        CHECK(c.upgradable == 3 && c.obsolete == 2);  /* as for the plain lists */

        /* A truncated file is an error, never a short but "valid" index. */
        st = gaudit_deb_scan(DATA "/status", make_lists(formats[i], 1), NULL, NULL, &c);
        if (st != GAUDIT_BACKEND_ERROR)
            fprintf(stderr, "%s truncated: status %d\n", formats[i], (int)st);
        CHECK(st == GAUDIT_BACKEND_ERROR);
    }

    /* A compression we cannot read: unknown, never a partial count. */
    gaudit_deb_counts c;
    CHECK(gaudit_deb_scan(DATA "/status", make_lists("bz2", 0), NULL, NULL, &c)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Host names with dots are not mistaken for a suffix. */
    CHECK(gaudit_reader_supports("archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages"));
    CHECK(gaudit_reader_supports("archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages.lz4"));
    CHECK(!gaudit_reader_supports("archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages.bz2"));
}

int main(void)
{
    /* Feature detection. */
    CHECK(gaudit_deb_present(DATA "/status", "/bin/sh") == 1);
    CHECK(gaudit_deb_present(DATA "/no-such-status", "/bin/sh") == 0);
    CHECK(gaudit_deb_present(DATA "/lists", "/bin/sh") == 0);          /* a directory */
    CHECK(gaudit_deb_present(DATA "/status", "/nonexistent/dpkg") == 0);
    CHECK(gaudit_deb_present(NULL, "/bin/sh") == 0);

    /* Version ordering, as dpkg --compare-versions. */
    EQUAL("1.0-1", "1.0-1");
    EQUAL("0:1.0", "1.0");
    EQUAL("1.0", "1.00");
    LESS("1.0", "1.0-1");          /* missing revision sorts first */
    LESS("1.0~rc1", "1.0");        /* tilde sorts before everything */
    LESS("1.0~~", "1.0~");
    LESS("1.0", "1.0a");
    LESS("1.0", "1.0+dfsg");
    LESS("1.9", "1.10");
    LESS("2.0", "1:0.9");          /* epoch wins */
    LESS("2.30-2ubuntu1", "2.30-2ubuntu1.1");
    LESS("6.8.0-40.40", "6.8.0-41.41");
    LESS("1.2.3-1", "1.2.3-10");

    /* Scan.
     *  a: same version offered                -> fine
     *  b: newer version in the archive        -> upgradable
     *  c: not offered at all                  -> obsolete
     *  d: only config files left              -> ignored
     *  linux-image-6.8.0-40-generic: gone     -> ignored (kept as fallback)
     *  e: newer only in backports (NotAutomatic, priority 100 < 500) -> fine
     *  f: newer only as a 10 % phased update  -> fine
     *  g: on hold, same version offered       -> fine
     *  h: installed 1:0.5 is newer than any offered (2.0) -> obsolete
     *  firefox: 159 from packages.mozilla.org; archive has 1:1snap1
     *  thunderbird: 137, only offered as archive 1:1snap1 */
    gaudit_deb_counts counts = { 99, 99 };

    /* Without preferences, the snap transitional packages (epoch 1) look
     * like upgrades for firefox and thunderbird. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 3);
    CHECK(counts.obsolete == 2);

    /* With a common pinning setup (mozilla at 1000, Ubuntu's firefox and thunderbird at -1):
     * nothing to upgrade there, and thunderbird is left without a source,
     * exactly as apt reports it. The .bak file is ignored, as apt does. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", DATA "/no-such-preferences",
                          DATA "/preferences.d", &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 1);
    CHECK(counts.obsolete == 3);

    /* The obsolete callback reports exactly the counted packages. */
    unsigned reported = 0;
    CHECK(gaudit_deb_scan_ex(DATA "/status", DATA "/lists", NULL, DATA "/preferences.d",
                             &counts, count_reported, &reported) == GAUDIT_BACKEND_OK);
    CHECK(reported == 3);

    /* Pinning we cannot follow: no guess. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-regex.d", &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-label.d", &counts)
          == GAUDIT_BACKEND_ERROR);

    /* An empty (corrupt) .lz4 index: cannot tell. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-mixed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-compressed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/no-such-dir", NULL, NULL, &counts)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Compressed indexes give the same answer as plain ones. */
    compressed_cases();

    /* Unreadable status file and bad arguments. */
    CHECK(gaudit_deb_scan(DATA "/no-such-status", DATA "/lists", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(NULL, DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, NULL) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
