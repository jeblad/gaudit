/* SPDX-License-Identifier: GPL-3.0-only */
/* MD5 (RFC 1321), only to compare files with dpkg's md5sums. Not for
 * anything that needs a secure hash: MD5 has known collisions, and the
 * md5sums are not signed after installation anyway. Written here so the
 * helper stays free of crypto libraries. */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint64_t length;        /* bytes so far */
    unsigned char block[64];
    size_t used;            /* bytes in block */
} gaudit_md5;

void gaudit_md5_init(gaudit_md5 *ctx);
void gaudit_md5_update(gaudit_md5 *ctx, const void *data, size_t len);
void gaudit_md5_final(gaudit_md5 *ctx, unsigned char digest[16]);

/* The digest as 32 lowercase hex digits and a NUL. */
void gaudit_md5_hex(const unsigned char digest[16], char hex[33]);
