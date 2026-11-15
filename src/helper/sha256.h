/* SPDX-License-Identifier: GPL-3.0-only */
/* SHA-256 (FIPS 180-4), for the register of files gAudit wrote: it tells
 * whether a file is still exactly what gAudit wrote. Written here so the
 * helper stays free of crypto libraries until it verifies the manifest. */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;        /* bytes so far */
    unsigned char block[64];
    size_t used;            /* bytes in block */
} gaudit_sha256;

void gaudit_sha256_init(gaudit_sha256 *ctx);
void gaudit_sha256_update(gaudit_sha256 *ctx, const void *data, size_t len);
void gaudit_sha256_final(gaudit_sha256 *ctx, unsigned char digest[32]);

/* The digest of data as 64 lowercase hex digits and a NUL. */
void gaudit_sha256_hex(const void *data, size_t len, char hex[65]);
