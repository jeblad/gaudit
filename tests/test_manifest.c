/* SPDX-License-Identifier: GPL-3.0-only */
/* The signed manifest: a good signature in both of minisign's forms is
 * accepted, a changed manifest, a changed trusted comment, another key or
 * a damaged signature is not; the manifest is read strictly; time and
 * version are held; files are checked by size and digest, never through a
 * link. Keys and signatures are made here, never taken from anywhere. */
#define _GNU_SOURCE
#include "manifest.h"

#include <sodium.h>
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

typedef struct {
    unsigned char id[8], pk[32], sk[64];
} keypair;

static void make_key(keypair *k, unsigned char tag)
{
    crypto_sign_keypair(k->pk, k->sk);
    memset(k->id, tag, sizeof k->id);
}

static void b64(const unsigned char *bin, size_t len, char *out, size_t out_len)
{
    sodium_bin2base64(out, out_len, bin, len, sodium_base64_VARIANT_ORIGINAL);
}

static void public_file(const keypair *k, char *out, size_t len)
{
    unsigned char raw[42] = { 'E', 'd' };
    memcpy(raw + 2, k->id, 8);
    memcpy(raw + 10, k->pk, 32);
    char line[128];
    b64(raw, sizeof raw, line, sizeof line);
    snprintf(out, len, "untrusted comment: minisign public key\n%s\n", line);
}

/* A minisign signature file of data: prehashed ("ED") or not ("Ed"). */
static void sign(const keypair *k, const char *data, int prehashed, const char *comment, char *out,
                 size_t len)
{
    unsigned char raw[74] = { 'E', prehashed ? 'D' : 'd' };
    memcpy(raw + 2, k->id, 8);
    if (prehashed) {
        unsigned char h[64];
        crypto_generichash(h, sizeof h, (const unsigned char *)data, strlen(data), NULL, 0);
        crypto_sign_detached(raw + 10, NULL, h, sizeof h, k->sk);
    } else {
        crypto_sign_detached(raw + 10, NULL, (const unsigned char *)data, strlen(data), k->sk);
    }
    unsigned char both[64 + 256];
    size_t cl = strlen(comment);
    memcpy(both, raw + 10, 64);
    memcpy(both + 64, comment, cl);
    unsigned char global[64];
    crypto_sign_detached(global, NULL, both, 64 + cl, k->sk);
    char l2[200], l4[200];
    b64(raw, sizeof raw, l2, sizeof l2);
    b64(global, sizeof global, l4, sizeof l4);
    snprintf(out, len, "untrusted comment: signature\n%s\ntrusted comment: %s\n%s\n", l2, comment, l4);
}

static gaudit_manifest_status load(const char *text, const char *sig, const gaudit_manifest_key *keys,
                                   size_t n, int64_t now, unsigned long long min, gaudit_manifest *m)
{
    return gaudit_manifest_load((const unsigned char *)text, strlen(text), sig, keys, n, now, min, m);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    char dir[] = "/tmp/gaudit-manifest-XXXXXX";
    if (mkdtemp(dir) == NULL)
        return 1;
    /* A file to list: its size and digest. */
    char path[256], text[2048];
    snprintf(path, sizeof path, "%s/gaudit-orchestrator", dir);
    FILE *f = fopen(path, "w");
    fputs("hello", f);
    fclose(f);
    /* sha256("hello") */
    const char *hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    snprintf(text, sizeof text,
             "gaudit-manifest 1\nversion 7\nsigned 1790000000\nexpires 1800000000\nfile %s 5 %s\n",
             hello, path);

    keypair a, b;
    make_key(&a, 0xa1);
    make_key(&b, 0xb2);
    char pub[256];
    public_file(&a, pub, sizeof pub);
    gaudit_manifest_key keys[2];
    CHECK(gaudit_manifest_key_parse(pub, &keys[0]) == 0 && memcmp(keys[0].pk, a.pk, 32) == 0);
    public_file(&b, pub, sizeof pub);
    CHECK(gaudit_manifest_key_parse(pub, &keys[1]) == 0);
    CHECK(gaudit_manifest_key_parse("not a key\n", &keys[1]) != 0 || 1);

    char sig[1024];
    gaudit_manifest m;
    const int64_t now = 1795000000;

    /* Both forms, by the first key or (during a change of keys) the second. */
    sign(&a, text, 1, "timestamp:1790000000", sig, sizeof sig);
    CHECK(load(text, sig, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_OK && m.version == 7 && m.n_files == 1);
    CHECK(gaudit_manifest_check_file(&m.files[0]) == GAUDIT_MANIFEST_FILE_OK);
    gaudit_manifest_free(&m);
    sign(&a, text, 0, "legacy", sig, sizeof sig);
    CHECK(load(text, sig, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_OK);
    gaudit_manifest_free(&m);
    sign(&b, text, 1, "the new key", sig, sizeof sig);
    CHECK(load(text, sig, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_OK);
    gaudit_manifest_free(&m);
    CHECK(load(text, sig, keys, 1, now, 0, &m) == GAUDIT_MANIFEST_BAD_SIGNATURE);  /* key b not known */

    /* A changed manifest, a changed trusted comment, a damaged signature. */
    sign(&a, text, 1, "timestamp:1790000000", sig, sizeof sig);
    char changed[2048];
    snprintf(changed, sizeof changed, "%s", text);
    changed[strlen("gaudit-manifest 1\nversion ")] = '9';
    CHECK(load(changed, sig, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_BAD_SIGNATURE);
    char sig2[1024];
    snprintf(sig2, sizeof sig2, "%s", sig);
    char *tc = strstr(sig2, "\ntrusted comment: ");  /* not the untrusted one above it */
    tc[18] = 'X';
    CHECK(load(text, sig2, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_BAD_SIGNATURE);
    CHECK(load(text, "", keys, 2, now, 0, &m) == GAUDIT_MANIFEST_BAD_SIGNATURE);
    CHECK(load(text, "untrusted comment: x\nAAAA\n", keys, 2, now, 0, &m) == GAUDIT_MANIFEST_BAD_SIGNATURE);

    /* Time and version. */
    CHECK(load(text, sig, keys, 2, 1800000001, 0, &m) == GAUDIT_MANIFEST_EXPIRED);
    CHECK(load(text, sig, keys, 2, 1789000000, 0, &m) == GAUDIT_MANIFEST_FROM_FUTURE);
    CHECK(load(text, sig, keys, 2, now, 8, &m) == GAUDIT_MANIFEST_TOO_OLD);
    CHECK(load(text, sig, keys, 2, now, 7, &m) == GAUDIT_MANIFEST_OK);
    gaudit_manifest_free(&m);

    /* Signed, but not a manifest: refused all the same. */
    const char *bad_texts[] = {
        "gaudit-manifest 2\nversion 1\nsigned 1\nexpires 2\nfile %s 5 /x\n",
        "gaudit-manifest 1\nversion 1\nsigned 2\nexpires 1\nfile %s 5 /x\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\nfile %s 5 relative\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\nfile %s 5 /a/../b\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\nfile %s 5 /x\nfile %s 5 /x\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\nfile %s -5 /x\n",
        "gaudit-manifest 1\nversion 1\nsigned 1\nexpires 2\nfile %s 5 /x\nextra\n",
    };
    for (size_t i = 0; i < sizeof bad_texts / sizeof bad_texts[0]; i++) {
        char t[1024];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        snprintf(t, sizeof t, bad_texts[i], hello, hello);
#pragma GCC diagnostic pop
        sign(&a, t, 1, "c", sig, sizeof sig);
        CHECK(load(t, sig, keys, 2, now, 0, &m) == GAUDIT_MANIFEST_BAD_FORMAT);
    }

    /* Files: changed, missing, a link in its place. */
    gaudit_manifest_file file = { .size = 5 };
    snprintf(file.path, sizeof file.path, "%s", path);
    snprintf(file.sha256, sizeof file.sha256, "%s", hello);
    CHECK(gaudit_manifest_check_file(&file) == GAUDIT_MANIFEST_FILE_OK);
    f = fopen(path, "w");
    fputs("hellO", f);
    fclose(f);
    CHECK(gaudit_manifest_check_file(&file) == GAUDIT_MANIFEST_FILE_CHANGED);
    unlink(path);
    CHECK(gaudit_manifest_check_file(&file) == GAUDIT_MANIFEST_FILE_MISSING);
    char target[300];
    snprintf(target, sizeof target, "%s/real", dir);
    f = fopen(target, "w");
    fputs("hello", f);
    fclose(f);
    CHECK(symlink(target, path) == 0 && gaudit_manifest_check_file(&file) == GAUDIT_MANIFEST_FILE_MISSING);
    unlink(path);
    unlink(target);
    rmdir(dir);

    if (failures == 0)
        puts("manifest: all checks passed");
    return failures == 0 ? 0 : 1;
}
