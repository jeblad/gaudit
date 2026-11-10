/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs the dnf collector and parses its output. Backend internal; exposed
 * in a private header for tests. */
#pragma once

#include "gaudit/backend.h"

typedef struct {
    unsigned installed;
    unsigned upgradable;
    unsigned extras;  /* installed, offered by no repository; install-only left out */
    unsigned above;   /* installed, offered only in a lower version; install-only left out */
} gaudit_dnf_state;

/* Strict parser for "(dnf (installed N) (upgradable N) (extras N) (above N))". */
int gaudit_dnf_parse(const char *text, gaudit_dnf_state *out);

/* The collector's "list" mode: every package without a source, through fn
 * (see gaudit_collector_sourceless). */
gaudit_backend_status gaudit_dnf_run_list(const char *dnf_bin, const char *probe_path,
                                          int timeout_ms, gaudit_sourceless_fn fn, void *ctx);

/* GAUDIT_BACKEND_UNAVAILABLE when dnf_bin is missing; otherwise as
 * gaudit_collector_run. */
gaudit_backend_status gaudit_dnf_run_probe(const char *dnf_bin, const char *probe_path,
                                           int timeout_ms, gaudit_dnf_state *out);
