/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs the Snap collector and parses its output. Backend internal; exposed
 * in a private header for tests. */
#pragma once

#include "gaudit/backend.h"

/* Strict parser for the collector's S-expression (see gaudit-snap-probe.c).
 * 0 on success, -1 otherwise. */
int gaudit_snap_parse(const char *text, gaudit_snap_state *out);

/* GAUDIT_BACKEND_UNAVAILABLE when snap_bin is missing (Snap not in use);
 * otherwise as gaudit_collector_run. */
gaudit_backend_status gaudit_snap_run_probe(const char *snap_bin, const char *probe_path,
                                            int timeout_ms, gaudit_snap_state *out);
