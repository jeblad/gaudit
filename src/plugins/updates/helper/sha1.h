/* SPDX-License-Identifier: GPL-3.0-only */
/* SHA-1 (FIPS 180-4), only to compare a vendor package's parts with the
 * digests its signature lists (dpkg-sig lists MD5 and SHA-1; both must
 * match). Not a secure hash on its own: SHA-1 has known collisions, which
 * is why such a signature is shown as weaker than expected. Written here
 * so the helper stays free of crypto libraries. */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[5];
    uint64_t length;        /* bytes so far */
    unsigned char block[64];
    size_t used;            /* bytes in block */
} gaudit_sha1;

void gaudit_sha1_init(gaudit_sha1 *ctx);
void gaudit_sha1_update(gaudit_sha1 *ctx, const void *data, size_t len);
void gaudit_sha1_final(gaudit_sha1 *ctx, unsigned char digest[20]);

/* The digest as 40 lowercase hex digits and a NUL. */
void gaudit_sha1_hex(const unsigned char digest[20], char hex[41]);
