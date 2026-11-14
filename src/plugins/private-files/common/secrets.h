/* SPDX-License-Identifier: GPL-3.0-only */
/* The deep scan's findings, between orchestrator and GUI
 * ("gaudit-orchestrator secrets"): one line per file, those others can
 * reach first, then a summary line, parsed strictly on the receiving side.
 * Never any content: path, why it looks secret, mode and who can reach it.
 *
 *   (secret (path "...") (reason "...") (mode M) (reach R) (owned 0|1) (exact 0|1))
 *   (secrets (status S) (count N) (shown M) (others A) (groups B) (truncated 0|1))  last
 *
 * path is relative to the home directory. exact is 0 when bytes in the
 * name had to be replaced to be sent, so the path shown is not the file's
 * real name and must not be put in a command. */
#pragma once

#include <stddef.h>

#include "gaudit/model.h"

#ifdef __cplusplus
extern "C" {
#endif

/* At most this many findings are sent; the summary counts them all. */
#define GAUDIT_SECRETS_MAX_SHOWN 100

typedef enum {
    GAUDIT_SECRET_OWNER = 0,      /* only the owner */
    GAUDIT_SECRET_OWN_GROUP = 1,  /* the owner's own private group: counts as the owner */
    GAUDIT_SECRET_GROUP = 2,      /* members of other groups on the way */
    GAUDIT_SECRET_OTHERS = 3,     /* every account on the machine */
    GAUDIT_SECRET_REACHES
} gaudit_secret_reach;

typedef struct {
    char path[256];
    char reason[32];   /* stable id, e.g. "pem-private-key" */
    unsigned mode;     /* permission bits */
    gaudit_secret_reach reach;
    int owned;         /* owned by the user */
    int exact;         /* path is the real name */
} gaudit_secret_finding;

typedef enum {
    GAUDIT_SECRETS_OK = 0,
    GAUDIT_SECRETS_UNKNOWN = 1,  /* the home directory could not be searched */
} gaudit_secrets_status;

typedef struct {
    gaudit_secrets_status status;
    unsigned count;      /* findings */
    unsigned shown;      /* lines sent before this one */
    unsigned others;     /* findings every account can reach */
    unsigned groups;     /* findings other groups can reach */
    int truncated;       /* the scan stopped at its entry limit */
} gaudit_secrets_summary;

int gaudit_secrets_format_finding(const gaudit_secret_finding *f, char *buf, size_t len);
int gaudit_secrets_format_summary(const gaudit_secrets_summary *s, char *buf, size_t len);

/* One line, strictly: 1 a finding (in *f), 2 the summary (in *s), -1 anything else. */
int gaudit_secrets_parse_line(const char *line, gaudit_secret_finding *f, gaudit_secrets_summary *s);

/* Warning when anyone but the user can reach a secret; unknown when the
 * search failed or stopped early; otherwise OK (secrets only the user can
 * read are normal, e.g. SSH keys). */
gaudit_verdict gaudit_secrets_verdict(const gaudit_secrets_summary *s);

#ifdef __cplusplus
}
#endif
