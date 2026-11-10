/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs the pacman collector and parses its output. Backend internal;
 * exposed in a private header for tests. */
#pragma once

#include "gaudit/backend.h"

typedef struct {
    unsigned installed;
    unsigned upgradable;
    unsigned foreign;  /* offered by no configured repository (pacman -Qm) */
    unsigned above;    /* offered only in a lower version */
} gaudit_pacman_state;

/* Strict parser for "(pacman (installed N) (upgradable N) (foreign N) (above N))". */
int gaudit_pacman_parse(const char *text, gaudit_pacman_state *out);

/* The collector's "list" mode: every package without a source, through fn
 * (see gaudit_collector_sourceless). */
gaudit_backend_status gaudit_pacman_run_list(const char *pacman_bin, const char *probe_path,
                                             int timeout_ms, gaudit_sourceless_fn fn, void *ctx);

/* GAUDIT_BACKEND_UNAVAILABLE when pacman_bin is missing; otherwise as
 * gaudit_collector_run. */
gaudit_backend_status gaudit_pacman_run_probe(const char *pacman_bin, const char *probe_path,
                                              int timeout_ms, gaudit_pacman_state *out);
