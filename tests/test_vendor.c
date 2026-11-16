/* SPDX-License-Identifier: GPL-3.0-only */
/* Known vendor packages, the helper's side: the signed list of parts is
 * read only from what sqv authenticated, sqv's answer only counts as good
 * with exactly one key named, Zoom's real signature checks as weak (SHA-1)
 * and a changed text not at all, the arguments
 * take only the download's own path, SHA-1 is right, the key file shipped
 * is the one the table vouches for, and a package is refused before any
 * signature is checked when it is missing or not signed. */
#include "sha1.h"
#include "vendor-pkg.h"
#include "vendor.h"

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

#define SIGNED_HEAD "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1\n\n"
#define SIGNED_BODY                                                                   \
    "Version: 4\nSigner: \nDate: Fri Oct 30 12:35:50 2026\nRole: builder\nFiles: \n"   \
    "\t3cf918272ffa5de195752d73f3da3e5e 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 debian-binary\n" \
    "\t848355632dfeecc84bb39246e34bb613 ef983da84b8fe16d3580978ce8d0ab2c13f79204 18352 control.tar.xz\n" \
    "\t1f4449adc837b2397a98b6b8d4ab26f6 dd433030d89f65596cf6eb291b34e34f51d1310b 304599012 data.tar.xz\n"
#define SIGNED_TAIL "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n=oE4i\n-----END PGP SIGNATURE-----\n"


/* SHA-1 of the first public key packet in a binary keyring: its v4
 * fingerprint, as 40 upper-case hex digits. */
static int key_fingerprint(const char *path, char out[41])
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 3)
        return -1;
    size_t hlen, blen;
    if ((buf[0] & 0xc0) == 0xc0) {          /* new format */
        if ((buf[0] & 0x3f) != 6)
            return -1;
        if (buf[1] < 192) {
            blen = buf[1];
            hlen = 2;
        } else if (buf[1] < 224) {
            blen = ((size_t)(buf[1] - 192) << 8) + buf[2] + 192;
            hlen = 3;
        } else {
            return -1;
        }
    } else if ((buf[0] & 0x80) == 0x80) {   /* old format */
        if (((buf[0] >> 2) & 0x0f) != 6)
            return -1;
        int lt = buf[0] & 3;
        if (lt == 0) {
            blen = buf[1];
            hlen = 2;
        } else if (lt == 1) {
            blen = (size_t)buf[1] << 8 | buf[2];
            hlen = 3;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
    if (hlen + blen > n || buf[hlen] != 4)
        return -1;
    gaudit_sha1 ctx;
    gaudit_sha1_init(&ctx);
    unsigned char pre[3] = { 0x99, (unsigned char)(blen >> 8), (unsigned char)blen };
    gaudit_sha1_update(&ctx, pre, 3);
    gaudit_sha1_update(&ctx, buf + hlen, blen);
    unsigned char d[20];
    gaudit_sha1_final(&ctx, d);
    for (int i = 0; i < 20; i++)
        snprintf(out + 2 * i, 3, "%02X", d[i]);
    return 0;
}

static char dir[] = "/tmp/gaudit-vendor-XXXXXX";

static int gaudit_vendor_listed_parts_file(const char *path)
{
    static char text[65536];
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = '\0';
    gaudit_vendor_part parts[8];
    return gaudit_vendor_listed_parts(text, parts, 8);
}

static int rm_one(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb; (void)flag; (void)ftw;
    return remove(path);
}

static void put(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f != NULL) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

int main(void)
{
    /* SHA-1, against FIPS 180's examples. */
    gaudit_sha1 ctx;
    unsigned char d[20];
    char hex[41];
    gaudit_sha1_init(&ctx);
    gaudit_sha1_update(&ctx, "abc", 3);
    gaudit_sha1_final(&ctx, d);
    gaudit_sha1_hex(d, hex);
    CHECK(strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
    gaudit_sha1_init(&ctx);
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    gaudit_sha1_update(&ctx, two, strlen(two));
    gaudit_sha1_final(&ctx, d);
    gaudit_sha1_hex(d, hex);
    CHECK(strcmp(hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1") == 0);

    /* The parts the authenticated text lists: dpkg-sig's, exactly. */
    gaudit_vendor_part parts[8];
    CHECK(gaudit_vendor_listed_parts(SIGNED_BODY, parts, 8) == 3);
    CHECK(strcmp(parts[2].name, "data.tar.xz") == 0 && parts[2].size == 304599012ULL
          && strcmp(parts[0].sha1, "7959c969e092f2a5a8604e2287807ac5b1b384ad") == 0);
    /* The builder's role, each part once, digests as digests. */
    CHECK(gaudit_vendor_listed_parts("Role: maintainer\nFiles: \n"
              "\t3cf918272ffa5de195752d73f3da3e5e 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 debian-binary\n",
              parts, 8) == -1);
    CHECK(gaudit_vendor_listed_parts(SIGNED_BODY
              "\t3cf918272ffa5de195752d73f3da3e5e 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 debian-binary\n",
              parts, 8) == -1);
    CHECK(gaudit_vendor_listed_parts("Role: builder\nFiles: \n\tnot-hex 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 x\n",
              parts, 8) == -1);
    CHECK(gaudit_vendor_listed_parts("", parts, 8) == -1);

    /* What sqv said: exactly one key named on success. */
    char fpr[41];
    CHECK(gaudit_vendor_sqv_result(0, "84C365D6CC9A4886CA926BCC4F2197399706AC24\n", fpr) == 0
          && strcmp(fpr, "84C365D6CC9A4886CA926BCC4F2197399706AC24") == 0);
    CHECK(gaudit_vendor_sqv_result(0, "84C365D6CC9A4886CA926BCC4F2197399706AC24\n"
                                      "84C365D6CC9A4886CA926BCC4F2197399706AC24\n", fpr) == -1);
    CHECK(gaudit_vendor_sqv_result(0, "", fpr) == -1);
    CHECK(gaudit_vendor_sqv_result(1, "84C365D6CC9A4886CA926BCC4F2197399706AC24\n", fpr) == -1);
    CHECK(gaudit_vendor_sqv_result(1, "Missing key 84C365D6CC9A4886CA926BCC4F2197399706AC24, which is "
                                      "needed to verify signature.\n", fpr) == -2);

    /* Only the download's own path, one word, nothing above it. */
    CHECK(gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "/home/u/.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "/home/u/.cache/gaudit/vendor/other.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "home/u/.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "/home/u/../x/.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "/home/u v/.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5.6661", "/etc//.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("zoom", "7.2.5-1", "/home/u/.cache/gaudit/vendor/zoom.deb"));
    CHECK(!gaudit_vendor_verify_args_ok("nope", "1", "/home/u/.cache/gaudit/vendor/nope.deb"));

    /* The key file shipped is the one the table vouches for. */
    char kf[41];
    const gaudit_vendor_package *zoom = gaudit_vendor_find("zoom");
    CHECK(zoom != NULL && key_fingerprint(KEYS_DIR "/zoom.gpg", kf) == 0
          && strcmp(kf, zoom->keys[zoom->n_keys - 1].fingerprint) == 0);

    /* Refused before any signature is checked. */
    if (mkdtemp(dir) == NULL)
        return 1;
    char cache[256], home[256], deb[300];
    snprintf(cache, sizeof cache, "%s/root/vendor", dir);
    snprintf(home, sizeof home, "%s/u/.cache/gaudit/vendor", dir);
    char mk[300];
    snprintf(mk, sizeof mk, "%s/root", dir);
    mkdir(mk, 0755);
    snprintf(mk, sizeof mk, "%s/u", dir);
    mkdir(mk, 0700);
    snprintf(mk, sizeof mk, "%s/u/.cache", dir);
    mkdir(mk, 0700);
    snprintf(mk, sizeof mk, "%s/u/.cache/gaudit", dir);
    mkdir(mk, 0700);
    mkdir(home, 0700);
    snprintf(deb, sizeof deb, "%s/zoom.deb", home);
    gaudit_vendor_env env = {
        .cache_dir = cache, .keys_dir = KEYS_DIR, .owner = getuid(), .check_key_owner = 0,
        .sqv = "/usr/bin/false", .dpkg_deb = "/usr/bin/false", .dpkg_query = "/usr/bin/false",
        .dpkg = "/usr/bin/false", .weak_policy = KEYS_DIR "/sha1-only.toml",
    };
    gaudit_vendor_outcome o;
    gaudit_vendor_verify(&env, "zoom", "7.2.5.6661", deb, &o);
    CHECK(strcmp(o.result, "no-file") == 0);
    /* An archive without _gpgbuilder: not signed. */
    static const char unsigned_deb[] =
        "!<arch>\n"
        "debian-binary   0           0     0     100644  4         `\n2.0\n"
        "control.tar.xz  0           0     0     100644  2         `\nab"
        "data.tar.xz     0           0     0     100644  2         `\ncd";
    put(deb, unsigned_deb, sizeof unsigned_deb - 1);
    gaudit_vendor_verify(&env, "zoom", "7.2.5.6661", deb, &o);
    CHECK(strcmp(o.result, "not-signed") == 0);
    /* Something else than a package. */
    put(deb, "not an archive", 14);
    gaudit_vendor_verify(&env, "zoom", "7.2.5.6661", deb, &o);
    CHECK(strcmp(o.result, "mismatch") == 0);
    /* A link where the download should be is never followed. */
    unlink(deb);
    if (symlink("/etc/hostname", deb) == 0) {
        gaudit_vendor_verify(&env, "zoom", "7.2.5.6661", deb, &o);
        CHECK(strcmp(o.result, "no-file") == 0);
    }
    /* sqv on Zoom's real signature: weak (SHA-1) but good, the key's
     * fingerprint named; one changed byte in the signed text, refused. */
    if (access("/usr/bin/sqv", X_OK) == 0) {
        gaudit_vendor_env real = env;
        real.sqv = "/usr/bin/sqv";
        char text[300], changed[300];
        snprintf(text, sizeof text, "%s/text.txt", dir);
        int weak = -1;
        CHECK(gaudit_vendor_sqv_check(&real, KEYS_DIR "/zoom.gpg", SIG_FILE, text, fpr, &weak) == 0
              && weak == 1 && strcmp(fpr, "84C365D6CC9A4886CA926BCC4F2197399706AC24") == 0);
        CHECK(gaudit_vendor_listed_parts_file(text) == 3);
        /* The same, with "builder" changed to "builded". */
        FILE *in = fopen(SIG_FILE, "r");
        char buf[8192];
        size_t n = in != NULL ? fread(buf, 1, sizeof buf - 1, in) : 0;
        if (in != NULL)
            fclose(in);
        buf[n] = '\0';
        char *role = strstr(buf, "Role: builder");
        if (role != NULL)
            memcpy(role + 6, "builded", 7);
        snprintf(changed, sizeof changed, "%s/changed.asc", dir);
        put(changed, buf, n);
        CHECK(gaudit_vendor_sqv_check(&real, KEYS_DIR "/zoom.gpg", changed, text, fpr, &weak) == -1);
        CHECK(access(text, F_OK) != 0);  /* nothing it wrote is left to read */
    } else {
        fputs("vendor: no /usr/bin/sqv, the real signature not checked\n", stderr);
    }

    /* Installing without a checked copy installs nothing; nothing is left behind. */
    gaudit_vendor_install(&env, "zoom", 1, &o);
    CHECK(strcmp(o.result, "not-verified") == 0);
    struct stat st;
    CHECK(stat(cache, &st) != 0);
    nftw(dir, rm_one, 8, FTW_DEPTH | FTW_PHYS);

    if (failures == 0)
        puts("vendor: all checks passed");
    return failures == 0 ? 0 : 1;
}
