/* SPDX-License-Identifier: GPL-3.0-only */
#include "compressed.h"

#include <lz4frame.h>
#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

#define CHUNK      (64 * 1024)
#define MAX_OUTPUT (1024LL * 1024 * 1024)  /* largest index we accept, decompressed */
#define MAX_LINE   (1024 * 1024)

typedef enum { FMT_PLAIN, FMT_GZ, FMT_XZ, FMT_LZ4, FMT_ZST } format;

struct gaudit_reader {
    format fmt;
    FILE *file;
    z_stream gz;
    int gz_ready;
    lzma_stream xz;
    LZ4F_dctx *lz4;
    ZSTD_DStream *zst;

    unsigned char in[CHUNK];
    size_t in_len, in_pos;
    int in_eof;

    size_t frame_hint;     /* lz4/zst: nonzero while a frame is incomplete */

    unsigned char out[CHUNK];
    size_t out_len, out_pos;
    long long produced;
    int eof, failed;
};

static int ends_with(const char *s, const char *suffix)
{
    size_t len = strlen(s), slen = strlen(suffix);
    return len >= slen && strcmp(s + len - slen, suffix) == 0;
}

static format format_of(const char *path)
{
    if (ends_with(path, ".gz"))  return FMT_GZ;
    if (ends_with(path, ".xz"))  return FMT_XZ;
    if (ends_with(path, ".lz4")) return FMT_LZ4;
    if (ends_with(path, ".zst")) return FMT_ZST;
    return FMT_PLAIN;
}

/* A compression suffix is a dot after the last '_' (apt list names contain
 * dots in the host part, e.g. "archive.ubuntu.com_..._Packages"). */
int gaudit_reader_supports(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *base = slash != NULL ? slash + 1 : path;
    const char *underscore = strrchr(base, '_');
    const char *dot = strrchr(base, '.');
    if (dot == NULL || (underscore != NULL && dot < underscore))
        return 1;  /* no suffix: plain */
    return format_of(base) != FMT_PLAIN;
}

gaudit_reader *gaudit_reader_open(const char *path)
{
    gaudit_reader *r = calloc(1, sizeof *r);
    if (r == NULL)
        return NULL;
    r->fmt = format_of(path);
    r->frame_hint = 1;  /* lz4/zst: no complete frame yet, so an empty file is an error */

    r->file = fopen(path, "rbe");
    if (r->file == NULL)
        goto fail;
    switch (r->fmt) {
    case FMT_GZ:
        /* inflate rather than gzread: gzread does not report a stream that
         * ends early (seen with zlib 1.3.2), inflate does (no Z_STREAM_END). */
        if (inflateInit2(&r->gz, 16 + MAX_WBITS) != Z_OK)
            goto fail;
        r->gz_ready = 1;
        break;
    case FMT_XZ: {
        lzma_stream init = LZMA_STREAM_INIT;
        r->xz = init;
        if (lzma_stream_decoder(&r->xz, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK)
            goto fail;
        break;
    }
    case FMT_LZ4:
        if (LZ4F_isError(LZ4F_createDecompressionContext(&r->lz4, LZ4F_VERSION)))
            goto fail;
        break;
    case FMT_ZST:
        r->zst = ZSTD_createDStream();
        if (r->zst == NULL || ZSTD_isError(ZSTD_initDStream(r->zst)))
            goto fail;
        break;
    case FMT_PLAIN:
    default:
        break;
    }
    return r;

fail:
    gaudit_reader_close(r);
    return NULL;
}

/* Raw input for the stream decoders. 0 at end of input, -1 on error. */
static int fill_input(gaudit_reader *r)
{
    if (r->in_pos < r->in_len)
        return 1;
    if (r->in_eof)
        return 0;
    r->in_len = fread(r->in, 1, sizeof r->in, r->file);
    r->in_pos = 0;
    if (r->in_len == 0) {
        if (ferror(r->file))
            return -1;
        r->in_eof = 1;
        return 0;
    }
    return 1;
}

/* Produces the next block of decompressed bytes into out. */
static void refill(gaudit_reader *r)
{
    r->out_len = r->out_pos = 0;
    while (r->out_len == 0 && !r->eof && !r->failed) {
        switch (r->fmt) {
        case FMT_PLAIN: {
            size_t n = fread(r->out, 1, sizeof r->out, r->file);
            if (n == 0) {
                if (ferror(r->file))
                    r->failed = 1;
                else
                    r->eof = 1;
            }
            r->out_len = n;
            break;
        }
        case FMT_GZ: {
            int more = fill_input(r);
            if (more < 0) {
                r->failed = 1;
                break;
            }
            if (!more) {
                /* Complete only if the last member reached its end. */
                if (r->frame_hint == 0)
                    r->eof = 1;
                else
                    r->failed = 1;  /* truncated */
                break;
            }
            if (r->frame_hint == 0 && inflateReset(&r->gz) != Z_OK) {  /* next member */
                r->failed = 1;
                break;
            }
            r->gz.next_in = r->in + r->in_pos;
            r->gz.avail_in = (uInt)(r->in_len - r->in_pos);
            r->gz.next_out = r->out;
            r->gz.avail_out = sizeof r->out;
            int ret = inflate(&r->gz, Z_NO_FLUSH);
            r->in_pos = r->in_len - r->gz.avail_in;
            r->out_len = sizeof r->out - r->gz.avail_out;
            if (ret == Z_STREAM_END)
                r->frame_hint = 0;
            else if (ret == Z_OK || (ret == Z_BUF_ERROR && r->out_len > 0))
                r->frame_hint = 1;
            else
                r->failed = 1;
            break;
        }
        case FMT_XZ: {
            int more = fill_input(r);
            if (more < 0) {
                r->failed = 1;
                break;
            }
            r->xz.next_in = r->in + r->in_pos;
            r->xz.avail_in = r->in_len - r->in_pos;
            r->xz.next_out = r->out;
            r->xz.avail_out = sizeof r->out;
            lzma_ret ret = lzma_code(&r->xz, more ? LZMA_RUN : LZMA_FINISH);
            r->in_pos = r->in_len - r->xz.avail_in;
            r->out_len = sizeof r->out - r->xz.avail_out;
            if (ret == LZMA_STREAM_END)
                r->eof = r->out_len == 0;
            else if (ret != LZMA_OK)
                r->failed = 1;
            else if (!more && r->out_len == 0)
                r->failed = 1;  /* truncated stream */
            break;
        }
        case FMT_LZ4: {
            int more = fill_input(r);
            if (more < 0) {
                r->failed = 1;
                break;
            }
            /* At the end of input: done if the last frame was complete
             * (hint 0); otherwise flush what the decoder still holds, and
             * if nothing comes out, the frame was cut short. */
            if (!more && r->frame_hint == 0) {
                r->eof = 1;
                break;
            }
            size_t src = more ? r->in_len - r->in_pos : 0, dst = sizeof r->out;
            size_t hint = LZ4F_decompress(r->lz4, r->out, &dst,
                                          more ? r->in + r->in_pos : NULL, &src, NULL);
            if (LZ4F_isError(hint) || (!more && dst == 0)) {
                r->failed = 1;
                break;
            }
            r->in_pos += src;
            r->out_len = dst;
            r->frame_hint = hint;
            break;
        }
        case FMT_ZST: {
            int more = fill_input(r);
            if (more < 0) {
                r->failed = 1;
                break;
            }
            /* Same end-of-input rule as lz4: 0 from the last call means the
             * frame was complete and fully flushed. */
            if (!more && r->frame_hint == 0) {
                r->eof = 1;
                break;
            }
            ZSTD_inBuffer in = { more ? r->in + r->in_pos : NULL, more ? r->in_len - r->in_pos : 0, 0 };
            ZSTD_outBuffer out = { r->out, sizeof r->out, 0 };
            size_t ret = ZSTD_decompressStream(r->zst, &out, &in);
            if (ZSTD_isError(ret) || (!more && out.pos == 0)) {
                r->failed = 1;
                break;
            }
            r->in_pos += in.pos;
            r->out_len = out.pos;
            r->frame_hint = ret;
            break;
        }
        }
        r->produced += (long long)r->out_len;
        if (r->produced > MAX_OUTPUT)
            r->failed = 1;
    }
}

ssize_t gaudit_reader_getline(gaudit_reader *r, char **line, size_t *cap)
{
    if (r == NULL || line == NULL || cap == NULL || r->failed)
        return -1;
    size_t len = 0;
    for (;;) {
        if (r->out_pos == r->out_len) {
            refill(r);
            if (r->failed)
                return -1;
            if (r->out_len == 0)
                break;  /* end of data */
        }
        unsigned char *start = r->out + r->out_pos;
        size_t avail = r->out_len - r->out_pos;
        unsigned char *nl = memchr(start, '\n', avail);
        size_t take = nl != NULL ? (size_t)(nl - start) + 1 : avail;
        if (len + take + 1 > MAX_LINE) {
            r->failed = 1;
            return -1;
        }
        if (len + take + 1 > *cap) {
            size_t ncap = *cap ? *cap : 256;
            while (ncap < len + take + 1)
                ncap *= 2;
            char *nline = realloc(*line, ncap);
            if (nline == NULL) {
                r->failed = 1;
                return -1;
            }
            *line = nline;
            *cap = ncap;
        }
        memcpy(*line + len, start, take);
        len += take;
        r->out_pos += take;
        if (nl != NULL)
            break;
    }
    if (len == 0)
        return -1;
    (*line)[len] = '\0';
    return (ssize_t)len;
}

int gaudit_reader_failed(const gaudit_reader *r)
{
    return r == NULL || r->failed;
}

void gaudit_reader_close(gaudit_reader *r)
{
    if (r == NULL)
        return;
    if (r->gz_ready)
        inflateEnd(&r->gz);
    if (r->fmt == FMT_XZ)
        lzma_end(&r->xz);
    if (r->lz4 != NULL)
        LZ4F_freeDecompressionContext(r->lz4);
    if (r->zst != NULL)
        ZSTD_freeDStream(r->zst);
    if (r->file != NULL)
        fclose(r->file);
    free(r);
}
