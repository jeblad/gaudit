/* SPDX-License-Identifier: GPL-3.0-only */
#include "sha1.h"

#include <stdio.h>
#include <string.h>

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void block(gaudit_sha1 *ctx, const unsigned char *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16
             | (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3],
             e = ctx->state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void gaudit_sha1_init(gaudit_sha1 *ctx)
{
    static const uint32_t init[5] = {
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u,
    };
    memcpy(ctx->state, init, sizeof init);
    ctx->length = 0;
    ctx->used = 0;
}

void gaudit_sha1_update(gaudit_sha1 *ctx, const void *data, size_t len)
{
    const unsigned char *p = data;
    ctx->length += len;
    while (len > 0) {
        size_t take = 64 - ctx->used < len ? 64 - ctx->used : len;
        memcpy(ctx->block + ctx->used, p, take);
        ctx->used += take;
        p += take;
        len -= take;
        if (ctx->used == 64) {
            block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

void gaudit_sha1_final(gaudit_sha1 *ctx, unsigned char digest[20])
{
    uint64_t bits = ctx->length * 8;
    unsigned char pad = 0x80;
    gaudit_sha1_update(ctx, &pad, 1);
    unsigned char zero = 0;
    while (ctx->used != 56)
        gaudit_sha1_update(ctx, &zero, 1);
    unsigned char len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (unsigned char)(bits >> (56 - 8 * i));
    gaudit_sha1_update(ctx, len, 8);
    for (int i = 0; i < 5; i++) {
        digest[4 * i] = (unsigned char)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (unsigned char)ctx->state[i];
    }
}

void gaudit_sha1_hex(const unsigned char digest[20], char hex[41])
{
    for (int i = 0; i < 20; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
}
