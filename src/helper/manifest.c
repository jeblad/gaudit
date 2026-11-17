/* SPDX-License-Identifier: GPL-3.0-only */
#include "manifest.h"

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 4096
#define SKEW      (10 * 60)  /* how far ahead of now a signing time may be */

/* The next line of text (without its newline) into line; the rest after it. */
static const char *next_line(const char *p, const char *end, char *line, size_t len, int *ok)
{
    const char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t n = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);
    *ok = n < len;
    if (*ok) {
        memcpy(line, p, n);
        line[n] = '\0';
    }
    return nl != NULL ? nl + 1 : end;
}

static int base64(const char *text, unsigned char *out, size_t want)
{
    size_t got = 0;
    return sodium_base642bin(out, want, text, strlen(text), NULL, &got, NULL,
                             sodium_base64_VARIANT_ORIGINAL) == 0 && got == want ? 0 : -1;
}

int gaudit_manifest_key_parse(const char *text, gaudit_manifest_key *key)
{
    if (text == NULL || key == NULL || sodium_init() < 0)
        return -1;
    const char *end = text + strlen(text);
    char line[256];
    int ok;
    const char *p = next_line(text, end, line, sizeof line, &ok);
    if (!ok || strncmp(line, "untrusted comment:", 18) != 0)
        return -1;
    next_line(p, end, line, sizeof line, &ok);
    unsigned char raw[42];
    if (!ok || base64(line, raw, sizeof raw) != 0 || raw[0] != 'E' || raw[1] != 'd')
        return -1;
    memcpy(key->id, raw + 2, 8);
    memcpy(key->pk, raw + 10, 32);
    return 0;
}

int gaudit_manifest_signature_ok(const unsigned char *data, size_t len, const char *sig,
                                 const gaudit_manifest_key *keys, size_t n_keys)
{
    if (data == NULL || sig == NULL || keys == NULL || sodium_init() < 0)
        return 0;
    const char *end = sig + strlen(sig);
    char line[1024], comment[1024];
    int ok;
    const char *p = next_line(sig, end, line, sizeof line, &ok);
    if (!ok || strncmp(line, "untrusted comment:", 18) != 0)
        return 0;
    p = next_line(p, end, line, sizeof line, &ok);
    unsigned char raw[74];
    if (!ok || base64(line, raw, sizeof raw) != 0)
        return 0;
    p = next_line(p, end, comment, sizeof comment, &ok);
    if (!ok || strncmp(comment, "trusted comment: ", 17) != 0)
        return 0;
    next_line(p, end, line, sizeof line, &ok);
    unsigned char global[64];
    if (!ok || base64(line, global, sizeof global) != 0)
        return 0;
    /* "ED": the signature is over BLAKE2b-512 of the data (minisign's
     * default); "Ed": over the data itself (its legacy form). */
    int prehashed = raw[0] == 'E' && raw[1] == 'D';
    if (!prehashed && !(raw[0] == 'E' && raw[1] == 'd'))
        return 0;
    const gaudit_manifest_key *key = NULL;
    for (size_t i = 0; i < n_keys && key == NULL; i++)
        if (memcmp(keys[i].id, raw + 2, 8) == 0)
            key = &keys[i];
    if (key == NULL)
        return 0;
    unsigned char hash[crypto_generichash_BYTES_MAX];
    if (prehashed) {
        if (crypto_generichash(hash, sizeof hash, data, len, NULL, 0) != 0)
            return 0;
        if (crypto_sign_verify_detached(raw + 10, hash, sizeof hash, key->pk) != 0)
            return 0;
    } else if (crypto_sign_verify_detached(raw + 10, data, len, key->pk) != 0) {
        return 0;
    }
    /* The trusted comment is signed together with the signature. */
    const char *tc = comment + 17;
    size_t tcl = strlen(tc);
    unsigned char *both = malloc(64 + tcl);
    if (both == NULL)
        return 0;
    memcpy(both, raw + 10, 64);
    memcpy(both + 64, tc, tcl);
    int good = crypto_sign_verify_detached(global, both, 64 + tcl, key->pk) == 0;
    free(both);
    return good;
}

static int number(const char *s, unsigned long long *out)
{
    if (s == NULL || *s < '0' || *s > '9' || strlen(s) > 18)  /* fits a signed 64-bit field */
        return -1;
    char *e;
    errno = 0;
    *out = strtoull(s, &e, 10);
    return errno == 0 && *e == '\0' ? 0 : -1;
}

static int plain_path(const char *p)
{
    if (p[0] != '/' || strlen(p) >= 256)
        return 0;
    for (const char *c = p; *c != '\0'; c++) {
        if ((unsigned char)*c <= 0x20 || *c == 0x7f)
            return 0;
        if (c[0] == '/' && (c[1] == '/' || (c[1] == '.' && (c[2] == '/' || c[2] == '\0'
                                                            || (c[2] == '.' && (c[3] == '/' || c[3] == '\0'))))))
            return 0;
    }
    return 1;
}

static int hex64(const char *s)
{
    if (strlen(s) != 64)
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return 0;
    return 1;
}

void gaudit_manifest_free(gaudit_manifest *m)
{
    if (m != NULL) {
        free(m->files);
        memset(m, 0, sizeof *m);
    }
}

int gaudit_manifest_parse(const char *text, size_t len, gaudit_manifest *m)
{
    if (text == NULL || m == NULL || memchr(text, '\0', len) != NULL)
        return -1;
    memset(m, 0, sizeof *m);
    const char *p = text, *end = text + len;
    char line[512];
    int ok;
    p = next_line(p, end, line, sizeof line, &ok);
    if (!ok || strcmp(line, "gaudit-manifest 1") != 0)
        return -1;
    static const char *const heads[] = { "version ", "signed ", "expires " };
    unsigned long long vals[3];
    for (int i = 0; i < 3; i++) {
        p = next_line(p, end, line, sizeof line, &ok);
        size_t hl = strlen(heads[i]);
        if (!ok || strncmp(line, heads[i], hl) != 0 || number(line + hl, &vals[i]) != 0)
            return -1;
    }
    m->version = vals[0];
    m->signed_at = (int64_t)vals[1];
    m->expires = (int64_t)vals[2];
    if (m->expires <= m->signed_at)
        return -1;
    m->files = calloc(MAX_FILES, sizeof *m->files);
    if (m->files == NULL)
        return -1;
    while (p < end) {
        p = next_line(p, end, line, sizeof line, &ok);
        if (!ok || m->n_files >= MAX_FILES || strncmp(line, "file ", 5) != 0)
            goto bad;
        char hash[80], size[32];
        int at = 0;
        if (sscanf(line + 5, "%79s %31s %n", hash, size, &at) != 2 || at == 0)
            goto bad;
        gaudit_manifest_file *f = &m->files[m->n_files];
        const char *path = line + 5 + at;
        if (!hex64(hash) || number(size, &f->size) != 0 || !plain_path(path))
            goto bad;
        memcpy(f->sha256, hash, 65);  /* 64 digits and the end, checked above */
        snprintf(f->path, sizeof f->path, "%s", path);
        for (size_t i = 0; i < m->n_files; i++)
            if (strcmp(m->files[i].path, f->path) == 0)
                goto bad;  /* each file once */
        m->n_files++;
    }
    if (m->n_files == 0)
        goto bad;
    return 0;
bad:
    gaudit_manifest_free(m);
    return -1;
}

gaudit_manifest_status gaudit_manifest_load(const unsigned char *data, size_t len, const char *sig,
                                            const gaudit_manifest_key *keys, size_t n_keys,
                                            int64_t now, unsigned long long min_version,
                                            gaudit_manifest *m)
{
    memset(m, 0, sizeof *m);
    /* The signature first: nothing unsigned is even parsed. */
    if (!gaudit_manifest_signature_ok(data, len, sig, keys, n_keys))
        return GAUDIT_MANIFEST_BAD_SIGNATURE;
    if (gaudit_manifest_parse((const char *)data, len, m) != 0)
        return GAUDIT_MANIFEST_BAD_FORMAT;
    gaudit_manifest_status st = GAUDIT_MANIFEST_OK;
    if (m->signed_at > now + SKEW)
        st = GAUDIT_MANIFEST_FROM_FUTURE;
    else if (now > m->expires)
        st = GAUDIT_MANIFEST_EXPIRED;
    else if (m->version < min_version)
        st = GAUDIT_MANIFEST_TOO_OLD;
    if (st != GAUDIT_MANIFEST_OK)
        gaudit_manifest_free(m);
    return st;
}

gaudit_manifest_file_status gaudit_manifest_check_file(const gaudit_manifest_file *f)
{
    int fd = open(f->path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0)
        return GAUDIT_MANIFEST_FILE_MISSING;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return GAUDIT_MANIFEST_FILE_MISSING;
    }
    if ((unsigned long long)st.st_size != f->size) {
        close(fd);
        return GAUDIT_MANIFEST_FILE_CHANGED;
    }
    gaudit_sha256 ctx;
    gaudit_sha256_init(&ctx);
    static unsigned char buf[1 << 16];
    unsigned long long total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return GAUDIT_MANIFEST_FILE_CHANGED;
        }
        if (n == 0)
            break;
        total += (unsigned long long)n;
        gaudit_sha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    unsigned char d[32];
    gaudit_sha256_final(&ctx, d);
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", d[i]);
    return total == f->size && strcmp(hex, f->sha256) == 0 ? GAUDIT_MANIFEST_FILE_OK
                                                           : GAUDIT_MANIFEST_FILE_CHANGED;
}

const char *gaudit_manifest_status_name(gaudit_manifest_status s)
{
    switch (s) {
    case GAUDIT_MANIFEST_OK:            return "ok";
    case GAUDIT_MANIFEST_BAD_SIGNATURE: return "bad-signature";
    case GAUDIT_MANIFEST_BAD_FORMAT:    return "bad-format";
    case GAUDIT_MANIFEST_EXPIRED:       return "expired";
    case GAUDIT_MANIFEST_TOO_OLD:       return "too-old";
    case GAUDIT_MANIFEST_FROM_FUTURE:   return "from-future";
    }
    return "unknown";
}
