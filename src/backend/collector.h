/* SPDX-License-Identifier: GPL-3.0-only */
/* Running a collector program and parsing its answer. Shared by all
 * collectors (Flatpak, Snap, ...). Backend internal; exposed for tests. */
#pragma once

#include <stddef.h>

#include "gaudit/backend.h"

/* Runs probe_path with an empty environment except HOME (from the password
 * database), stdin and stderr on /dev/null, and a timeout. Its stdout is
 * stored NUL-terminated in buf; more than buf_len - 1 bytes is an error.
 *
 * GAUDIT_BACKEND_NOT_IMPLEMENTED     probe_path missing: built without it
 * GAUDIT_BACKEND_MISSING_DEPENDENCY  it could not start (exit 127, e.g. a
 *                                    shared library is missing)
 * GAUDIT_BACKEND_ERROR               any other failure, timeout, too much output
 * GAUDIT_BACKEND_OK                  exit 0; buf holds the output */
gaudit_backend_status gaudit_collector_run(const char *probe_path, int timeout_ms,
                                           char *buf, size_t buf_len);

/* As gaudit_collector_run, with one argument (NULL for none), e.g. "list". */
gaudit_backend_status gaudit_collector_run_arg(const char *probe_path, const char *arg,
                                               int timeout_ms, char *buf, size_t buf_len);

/* A collector's list of packages without a source, one line each, then
 * the count, strictly:
 *
 *   (package (name "...") (arch "...") (version "...") (group G) (offered "..."))
 *   (end (count N))
 *
 * offered is "" unless G is GAUDIT_SOURCELESS_ABOVE_SOURCE. fn is called
 * per package as it is parsed, so on an error some calls have been made:
 * the caller must then drop them. GAUDIT_BACKEND_OK only if every line is
 * valid and the count matches. */
gaudit_backend_status gaudit_collector_sourceless(const char *text, gaudit_sourceless_fn fn,
                                                  void *ctx);

typedef struct {
    const char *key;
    long long *value;  /* integer field (NULL for a text field) */
    long long max;     /* integers are min..max; |min|, max below LLONG_MAX / 10 */
    long long min;     /* 0 unless negative values are allowed */
    char *text;        /* text field: "..." with \" and \\ escapes, printable only */
    size_t text_len;   /* buffer size; longer text is an error */
} gaudit_sexpr_field;

/* Strict parser for "(head (key value) ...)": every field exactly once, in
 * any order, values of the declared type and range, nothing else.
 * 0 on success, -1 otherwise. */
int gaudit_sexpr_parse(const char *text, const char *head,
                       const gaudit_sexpr_field *fields, size_t n_fields);
