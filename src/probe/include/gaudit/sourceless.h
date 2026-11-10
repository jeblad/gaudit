/* SPDX-License-Identifier: GPL-3.0-only */
/* The list of packages without a source, between orchestrator and GUI
 * ("gaudit-orchestrator packages"): one line per package, then a summary
 * line, parsed strictly on the receiving side.
 *
 *   (package (name "...") (arch "...") (version "...") (group G) (offered "..."))
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
