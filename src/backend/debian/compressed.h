/* SPDX-License-Identifier: GPL-3.0-only */
/* Line reader for apt's package indexes, which may be stored compressed
 * (.gz, .xz, .lz4, .zst). Backend internal. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

typedef struct gaudit_reader gaudit_reader;

/* 1 if this file name has a compression suffix the reader can read (or none). */
int gaudit_reader_supports(const char *path);

/* Opens path, choosing the format by its suffix. NULL on failure. */
gaudit_reader *gaudit_reader_open(const char *path);

/* Like getline(3): returns the line length, -1 at end of file or on error
 * (tell them apart with gaudit_reader_failed). */
ssize_t gaudit_reader_getline(gaudit_reader *r, char **line, size_t *cap);

/* 1 if reading failed: corrupt data, an I/O error, or more output than the
 * limit allows (a guard against decompression bombs). */
int gaudit_reader_failed(const gaudit_reader *r);

void gaudit_reader_close(gaudit_reader *r);
