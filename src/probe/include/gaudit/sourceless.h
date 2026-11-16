/* SPDX-License-Identifier: GPL-3.0-only */
/* The list of packages without a source, between orchestrator and GUI
 * ("gaudit-orchestrator packages"): one line per package, then a summary
 * line, parsed strictly on the receiving side.
 *
 *   (package (name "...") (arch "...") (version "...") (group G) (offered "...")
 *            (replaced "...") (needed-by N) (needed "...") (manual M) (installed T)
 *            (program P) (built-for "...") (likely-source "..."))
 *
 * The last six help judge a package, nothing more: replaced "flatpak <id>"
 * or "snap <name>" (probably replaced) or ""; needed-by -1 unknown, needed
 * the first names; manual 1 on purpose, 0 as a dependency, -1 unknown;
 * installed a time (seconds since 1970), 0 unknown; program 1 when it
 * installs a program people start themselves, 0 not, -1 unknown; built-for
 * the older release its version names ("Ubuntu 25.10"), or ""; likely-source
 * the sources switched off at an upgrade that were for that release.
 *   (packages (status S) (count N) (shown M))   always last */
#pragma once

#include <stddef.h>

#include "gaudit/backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/* At most this many packages are sent; the summary says how many there are. */
#define GAUDIT_SOURCELESS_MAX_SHOWN 300

typedef struct {
    char name[128];
    char arch[32];
    char version[96];
    char offered[96];   /* "" unless the group is ABOVE_SOURCE */
    gaudit_sourceless_group group;
    char replaced[96];
    int needed_by;
    char needed[128];
    int manual;
    long long installed;
    int program;
    char built_for[32];
    char likely_source[128];
} gaudit_sourceless_package;

typedef enum {
    GAUDIT_SOURCELESS_OK = 0,
    GAUDIT_SOURCELESS_UNSUPPORTED = 1,  /* the backend cannot list them */
    GAUDIT_SOURCELESS_UNKNOWN = 2,      /* could not find out */
} gaudit_sourceless_status;

typedef struct {
    gaudit_sourceless_status status;
    unsigned count;   /* packages without a source */
    unsigned shown;   /* lines sent before this one */
} gaudit_sourceless_summary;

int gaudit_sourceless_format_package(const gaudit_sourceless_package *p, char *buf, size_t len);
int gaudit_sourceless_format_summary(const gaudit_sourceless_summary *s, char *buf, size_t len);

/* One line, strictly: 1 a package (in *p), 2 the summary (in *s), -1 anything else. */
int gaudit_sourceless_parse_line(const char *line, gaudit_sourceless_package *p,
                                 gaudit_sourceless_summary *s);

#ifdef __cplusplus
}
#endif
