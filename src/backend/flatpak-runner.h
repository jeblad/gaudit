/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs the Flatpak collector as a separate process and parses its output.
 * Backend internal; exposed in a private header for tests. */
#pragma once

#include "gaudit/backend.h"

/* Strict parser for "(flatpak (apps N) (eol-apps N) (eol-unused N) (eol-pinned N))".
 * Every key exactly once, nothing else. 0 on success, -1 otherwise. */
int gaudit_flatpak_parse(const char *text, gaudit_flatpak_state *out);

/* GAUDIT_BACKEND_UNAVAILABLE         flatpak_bin missing: Flatpak not in use
 * GAUDIT_BACKEND_NOT_IMPLEMENTED     probe_path missing: built without support
 * GAUDIT_BACKEND_MISSING_DEPENDENCY  the collector could not start (exit 127)
 * GAUDIT_BACKEND_ERROR               failure, timeout, too much or bad output
 * The collector gets an empty environment except HOME (taken from the
 * password database, not inherited), stdin/stderr on /dev/null. */
gaudit_backend_status gaudit_flatpak_run_probe(const char *flatpak_bin, const char *probe_path,
                                               int timeout_ms, gaudit_flatpak_state *out);
