/* SPDX-License-Identifier: GPL-3.0-only */
/* dpkg version ordering and the installed-vs-available scan on fixtures in
 * tests/data/dpkg/. */
#include "dpkg.h"

#include "compressed.h"

#include <dirent.h>
#include <lz4frame.h>
#include <lzma.h>
#include <stdint.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>
#include <zlib.h>
#include <zstd.h>

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

#define LESS(a, b)  CHECK(gaudit_deb_version_compare(a, b) < 0 && gaudit_deb_version_compare(b, a) > 0)
#define EQUAL(a, b) CHECK(gaudit_deb_version_compare(a, b) == 0)

#define DATA GAUDIT_TEST_DATA_DIR "/dpkg"

/* Which group each sourceless package lands in, and what is offered. */
static void count_reported(const char *name, const char *arch, const char *version,
                           gaudit_deb_group group, const char *offered, void *ctx)
{
    (void)arch;
    (void)version;
    if (strcmp(name, "h") == 0)            /* 1:0.5 installed, only 2.0 offered */
        CHECK(group == GAUDIT_SOURCELESS_ABOVE_SOURCE && offered != NULL && strcmp(offered, "2.0") == 0);
    else if (strcmp(name, "oldlib") == 0)  /* Ubuntu maintainer, offered nowhere */
        CHECK(group == GAUDIT_SOURCELESS_LEFTOVER && offered == NULL);
    else if (strcmp(name, "changed") == 0) /* Original-Maintainer: changed by the distribution */
        CHECK(group == GAUDIT_SOURCELESS_LEFTOVER);
    else if (strcmp(name, "c") == 0 || strcmp(name, "vendor-tool") == 0)
        CHECK(group == GAUDIT_SOURCELESS_OTHER_SOURCE && offered == NULL);
    else if (strcmp(name, "thunderbird") == 0)
        /* Offered only above (1:1snap1) and pinned away: not "above the
         * source"; no distribution maintainer in the fixture. */
        CHECK(group == GAUDIT_SOURCELESS_OTHER_SOURCE);
    else
        CHECK(!"unexpected package");
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
        gaudit_deb_counts c = { 99, 99, 99 };
        gaudit_backend_status st = gaudit_deb_scan(DATA "/status", make_lists(formats[i], 0),
                                                   NULL, NULL, &c);
        if (st != GAUDIT_BACKEND_OK || c.upgradable != 3 || c.obsolete != 2)
            fprintf(stderr, "%s: status %d, upgradable %u, obsolete %u\n",
                    formats[i], (int)st, c.upgradable, c.obsolete);
        CHECK(st == GAUDIT_BACKEND_OK);
        CHECK(c.upgradable == 3 && c.obsolete == 5);  /* as for the plain lists */

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

/* The details of a package, on a tree made here: who needs it, how and
 * when it was installed, and whether a Flatpak or a snap replaced it. */
static void put_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

/* The release a version says it was built for, when older than this one. */
static void built_for_cases(void)
{
    char out[32];
    CHECK(gaudit_deb_built_for("1.4.13-0~202604150752~ubuntu25.10.1", "ubuntu", "26.10", out, sizeof out)
          && strcmp(out, "Ubuntu 25.10") == 0);
    CHECK(gaudit_deb_built_for("1.2-3ubuntu0.24.04.1", "ubuntu", "26.10", out, sizeof out)
          && strcmp(out, "Ubuntu 24.04") == 0);
    CHECK(!gaudit_deb_built_for("1.4.13~ubuntu26.10.1", "ubuntu", "26.10", out, sizeof out));
    CHECK(!gaudit_deb_built_for("2.0-1ubuntu3", "ubuntu", "26.10", out, sizeof out));      /* no release */
    CHECK(!gaudit_deb_built_for("1.0~ubuntu27.04", "ubuntu", "26.10", out, sizeof out));   /* newer */
    CHECK(gaudit_deb_built_for("2.36-9+deb12u7", "debian", "13", out, sizeof out)
          && strcmp(out, "Debian 12") == 0);
    CHECK(!gaudit_deb_built_for("2.41-6+deb13u1", "debian", "13", out, sizeof out));
    CHECK(!gaudit_deb_built_for("1.0+debian1", "debian", "13", out, sizeof out));
    CHECK(!gaudit_deb_built_for("1.0~ubuntu25.10", "fedora", "45", out, sizeof out));
}

/* An update for the release before, kept at the upgrade: above the source,
 * by the distribution, versioned as an update, installed before base-files
 * (the upgrade); one installed after it stays newer than the source. */
static int kept_libx11, kept_foo, kept_other;

static void record_group(const char *name, const char *arch, const char *version,
                         gaudit_deb_group group, const char *offered, void *ctx)
{
    (void)arch; (void)version; (void)offered; (void)ctx;
    if (strcmp(name, "libx11-6") == 0)
        kept_libx11 = (int)group;
    else if (strcmp(name, "foo") == 0)
        kept_foo = (int)group;
    else if (strcmp(name, "bar") == 0)
        kept_other = (int)group;
}

static void kept_cases(void)
{
    char root[1100], status[1200], lists[1200], info[1200], path[1400];
    snprintf(root, sizeof root, "%s/kept", tmp_dir);
    mkdir(root, 0755);
    snprintf(status, sizeof status, "%s/status", root);
    snprintf(lists, sizeof lists, "%s/lists", root);
    snprintf(info, sizeof info, "%s/info", root);
    mkdir(lists, 0755);
    mkdir(info, 0755);
    put_text(status,
             "Package: base-files\nStatus: install ok installed\nArchitecture: amd64\n"
             "Version: 14ubuntu1\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\n"
             "Package: libx11-6\nStatus: install ok installed\nArchitecture: amd64\n"
             "Version: 2:1.8.13-1ubuntu0.1\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\n"
             "Package: foo\nStatus: install ok installed\nArchitecture: amd64\n"
             "Version: 1.0-1ubuntu0.1\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\n"
             "Package: bar\nStatus: install ok installed\nArchitecture: amd64\n"
             "Version: 3.0-1ubuntu1\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n\n");
    snprintf(path, sizeof path, "%s/archive.ubuntu.com_ubuntu_dists_stonking_main_binary-amd64_Packages", lists);
    put_text(path,
             "Package: base-files\nArchitecture: amd64\nVersion: 14ubuntu1\n\n"
             "Package: libx11-6\nArchitecture: amd64\nVersion: 2:1.8.13-1\n\n"
             "Package: foo\nArchitecture: amd64\nVersion: 1.0-1\n\n"
             "Package: bar\nArchitecture: amd64\nVersion: 3.0-1\n\n");
    snprintf(path, sizeof path, "%s/archive.ubuntu.com_ubuntu_dists_stonking_InRelease", lists);
    put_text(path, "Origin: Ubuntu\nLabel: Ubuntu\nSuite: stonking\nCodename: stonking\n");
    /* base-files replaced now; libx11-6 and bar long before, foo since. */
    time_t now = time(NULL);
    struct utimbuf old = { now - 86400 * 30, now - 86400 * 30 }, later = { now + 60, now + 60 };
    snprintf(path, sizeof path, "%s/base-files.list", info);
    put_text(path, "/etc/os-release\n");
    snprintf(path, sizeof path, "%s/libx11-6:amd64.list", info);
    put_text(path, "/usr/lib/x86_64-linux-gnu/libX11.so.6\n");
    utime(path, &old);
    snprintf(path, sizeof path, "%s/bar.list", info);
    put_text(path, "/usr/bin/bar\n");
    utime(path, &old);
    snprintf(path, sizeof path, "%s/foo.list", info);
    put_text(path, "/usr/bin/foo\n");
    utime(path, &later);
    gaudit_deb_counts counts;
    kept_libx11 = kept_foo = kept_other = -1;
    snprintf(path, sizeof path, "%s/no-such-preferences.d", root);
    CHECK(gaudit_deb_scan_ex(status, lists, NULL, path, &counts, record_group, NULL) == GAUDIT_BACKEND_OK);
    CHECK(kept_libx11 == GAUDIT_SOURCELESS_KEPT);
    CHECK(kept_foo == GAUDIT_SOURCELESS_ABOVE_SOURCE);    /* installed after the upgrade */
    CHECK(kept_other == GAUDIT_SOURCELESS_ABOVE_SOURCE);  /* not versioned as an update */

    CHECK(gaudit_deb_update_version("2:1.8.13-1ubuntu0.1") && gaudit_deb_update_version("1.2-3ubuntu0.24.04.1")
          && gaudit_deb_update_version("2.36-9+deb12u7"));
    CHECK(!gaudit_deb_update_version("3.0-1ubuntu1") && !gaudit_deb_update_version("1.0+debian1")
          && !gaudit_deb_update_version("1.0-1ubuntu0") && !gaudit_deb_update_version("1.0+deb12"));
}

static void details_cases(void)
{
    char root[1100], path[1400], status[1200], info[1200], ext[1200], flat[1200], snap[1200];
    snprintf(root, sizeof root, "%s/details", tmp_dir);
    mkdir(root, 0755);
    snprintf(status, sizeof status, "%s/status", root);
    put_text(status,
        "Package: rhythmbox\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.4\n\n"
        "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n"
        "Package: tool\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n"
        "Depends: libfoo (>= 1.0), libc6\n\n"
        "Package: other\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n"
        "Pre-Depends: libbar | libfoo:any\n\n"
        "Package: gone\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1\n"
        "Depends: libfoo\n\n"
        "Package: firefox\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n"
        "Package: mainline\nStatus: install ok installed\nArchitecture: amd64\n"
        "Version: 1.4.13-0~202604150752~ubuntu25.10.1\n");
    snprintf(info, sizeof info, "%s/info", root);
    mkdir(info, 0755);
    snprintf(path, sizeof path, "%s/rhythmbox.list", info);
    put_text(path, "/usr/bin/rhythmbox\n/usr/share/metainfo/org.gnome.Rhythmbox3.appdata.xml\n"
                     "/usr/share/applications/org.gnome.Rhythmbox3.desktop\n");
    snprintf(path, sizeof path, "%s/libfoo:amd64.list", info);
    put_text(path, "/usr/lib/libfoo.so.1\n");
    snprintf(path, sizeof path, "%s/firefox.list", info);
    put_text(path, "/usr/share/applications/firefox.desktop\n");
    snprintf(ext, sizeof ext, "%s/extended_states", root);
    put_text(ext, "Package: libfoo\nArchitecture: amd64\nAuto-Installed: 1\n\n");
    snprintf(flat, sizeof flat, "%s/flatpak", root);
    mkdir(flat, 0755);
    snprintf(path, sizeof path, "%s/org.gnome.Rhythmbox3", flat);
    mkdir(path, 0755);
    snprintf(snap, sizeof snap, "%s/snap", root);
    mkdir(snap, 0755);
    snprintf(path, sizeof path, "%s/firefox", snap);
    mkdir(path, 0755);
    /* The PPA the upgrade switched off, and distro-info's table. */
    char sources[1200], csv[1200];
    snprintf(sources, sizeof sources, "%s/sources.list.d", root);
    mkdir(sources, 0755);
    snprintf(path, sizeof path, "%s/cappelikan-ubuntu-ppa-questing.sources", sources);
    put_text(path, "Types: deb\nURIs: https://ppa.launchpadcontent.net/cappelikan/ppa/ubuntu/\n"
                   "Suites: questing\nComponents: main\nEnabled: no\n");
    snprintf(path, sizeof path, "%s/cappelikan-ubuntu-ppa-questing.sources.distUpgrade", sources);
    put_text(path, "Types: deb\nURIs: https://ppa.launchpadcontent.net/cappelikan/ppa/ubuntu/\n"
                   "Suites: questing\n");
    snprintf(csv, sizeof csv, "%s/ubuntu.csv", root);
    put_text(csv, "version,codename,series,created,release,eol\n"
                  "25.10,Questing Quokka,questing,2025-04-17,2025-10-09,2026-07-09\n"
                  "26.04 LTS,Resolute Raccoon,resolute,2025-10-16,2026-04-23,2031-05-29\n");
    const char *flatpak_dirs[] = { flat, NULL };
    gaudit_deb_paths paths = { .os_id = "ubuntu", .os_version_id = "26.10", .status_file = status,
                               .info_dir = info, .extended_states = ext,
                               .flatpak_dirs = flatpak_dirs, .snap_dir = snap,
                               .sources_dir = sources, .distro_info = csv };

    gaudit_package_details d;
    CHECK(gaudit_deb_package_details(&paths, "libfoo", "amd64", &d) == 0);
    /* tool and other need it (an alternative counts); a removed one does not. */
    CHECK(d.needed_by == 2 && strcmp(d.needed_names, "tool, other") == 0);
    CHECK(d.manual == 0 && d.installed > 0 && d.replaced[0] == '\0' && d.program == 0);

    CHECK(gaudit_deb_package_details(&paths, "rhythmbox", "amd64", &d) == 0);
    CHECK(strcmp(d.replaced, "flatpak org.gnome.Rhythmbox3") == 0);
    CHECK(d.needed_by == 0 && d.manual == 1 && d.program == 1);

    CHECK(d.built_for[0] == '\0' && d.likely_source[0] == '\0');  /* 3.4 names no release */

    /* Built for 25.10, and the PPA for questing (25.10) was switched off at
     * the upgrade: probably from there. */
    CHECK(gaudit_deb_package_details(&paths, "mainline", "amd64", &d) == 0);
    CHECK(strcmp(d.built_for, "Ubuntu 25.10") == 0);
    CHECK(strcmp(d.likely_source, "ppa:cappelikan/ppa") == 0);
    /* Running 26.04 instead, a package built for 25.10 still matches; one
     * built for no release named matches nothing. */
    CHECK(gaudit_deb_package_details(&paths, "libfoo", "amd64", &d) == 0 && d.likely_source[0] == '\0');

    /* A snap by the desktop file's name. */
    CHECK(gaudit_deb_package_details(&paths, "firefox", "amd64", &d) == 0);
    CHECK(strcmp(d.replaced, "snap firefox") == 0);

    /* Nothing to read: unknown, not none. */
    gaudit_deb_paths none = { 0 };
    CHECK(gaudit_deb_package_details(&none, "libfoo", "amd64", &d) == 0);
    CHECK(d.needed_by == -1 && d.manual == -1 && d.installed == 0);
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
    gaudit_deb_counts counts = { 99, 99, 99 };

    /* Without preferences, the snap transitional packages (epoch 1) look
     * like upgrades for firefox and thunderbird. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 3);
    CHECK(counts.obsolete == 5);  /* c, h, oldlib, changed, vendor-tool */

    /* With a common pinning setup (mozilla at 1000, Ubuntu's firefox and thunderbird at -1):
     * nothing to upgrade there, and thunderbird is left without a source,
     * exactly as apt reports it. The .bak file is ignored, as apt does. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", DATA "/no-such-preferences",
                          DATA "/preferences.d", &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 1);
    CHECK(counts.obsolete == 6);  /* ... and thunderbird */

    /* The obsolete callback reports exactly the counted packages. */
    unsigned reported = 0;
    CHECK(gaudit_deb_scan_ex(DATA "/status", DATA "/lists", NULL, DATA "/preferences.d",
                             &counts, count_reported, &reported) == GAUDIT_BACKEND_OK);
    CHECK(reported == 6);

    /* Pinning we cannot follow: no guess. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-regex.d", &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-label.d", &counts)
          == GAUDIT_BACKEND_ERROR);

    /* An empty (corrupt) .lz4 index: cannot tell. */
    /* Which tools are installed, by the status: a and g are, zz is not, and
     * the continuation line naming another package is no package. */
    {
        static const char *const names[] = { "zz", "g", "a", NULL };
        char found[64];
        unsigned n = 9;
        CHECK(gaudit_deb_installed_names(DATA "/status", names, found, sizeof found, &n) == 0
              && n == 2 && strcmp(found, "g, a") == 0);
        CHECK(gaudit_deb_installed_names(DATA "/no-such-status", names, found, sizeof found, &n) != 0);
    }

    /* An installed package's version; one not installed is not found. */
    {
        char v[64];
        CHECK(gaudit_deb_installed_version(DATA "/status", "c", v, sizeof v) == 1 && strcmp(v, "2.0") == 0);
        CHECK(gaudit_deb_installed_version(DATA "/status", "zz", v, sizeof v) == 0);
    }

    /* Security updates: a has a newer version in noble-security, and an
     * even newer one in noble-updates (Ubuntu puts security fixes there
     * too), so it counts; b is newer only in -updates; f's security update
     * is phased and held back. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-security", NULL, NULL, &counts)
          == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 2 && counts.security == 1);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_OK
          && counts.security == 0);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-mixed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-compressed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/no-such-dir", NULL, NULL, &counts)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Compressed indexes give the same answer as plain ones. */
    compressed_cases();

    details_cases();
    kept_cases();
    built_for_cases();

    /* Unreadable status file and bad arguments. */
    CHECK(gaudit_deb_scan(DATA "/no-such-status", DATA "/lists", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(NULL, DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, NULL) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s)\n", failures, tmp_dir);
    else
        nftw(tmp_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS);  /* kept on failure, to look at */
    return failures ? 1 : 0;
}
