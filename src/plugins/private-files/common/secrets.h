/* SPDX-License-Identifier: GPL-3.0-only */
/* The collection's lines, between orchestrator and GUI ("gaudit-orchestrator
 * secrets quick|full [folder ...]"): the areas searched, one line per file,
 * those others can reach first, then a summary line, parsed strictly on the
 * receiving side. Never any content: path, why it looks secret, mode and
 * who can reach it.
 *
 *   (area (index I) (path "...") (status S) (remote 0|1) (exact 0|1))  first, one per area
 *   (secret (area I) (path "...") (reason "...") (mode M) (reach R) (owned 0|1) (exact 0|1))
 *   (secrets (status S) (count N) (shown M) (others A) (groups B) (truncated 0|1))  last
 *
 * Area 0 is the home folder (its path is the home folder's); the others
 * are folders the user added, absolute. A finding's path is relative to
 * its area. remote: the area is on a network filesystem, where modes and
 * owners may not say who can reach a file on the server. exact is 0 when
 * bytes had to be replaced to be sent, so the path shown is not the real
 * name and must not be put in a command. */
#pragma once

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

/* At most this many findings are sent; the summary counts them all. */
#define GAUDIT_SECRETS_MAX_SHOWN 100
/* The home folder and at most this many added folders. */
#define GAUDIT_SECRETS_MAX_AREAS 16

typedef enum {
    GAUDIT_AREA_SEARCHED = 0,
    GAUDIT_AREA_UNREADABLE = 1,  /* could not be opened */
    GAUDIT_AREA_OVERLAPS = 2,    /* inside the home folder or another area, or holding one: skipped */
    GAUDIT_AREA_STATUSES
} gaudit_area_status;

typedef struct {
    unsigned index;
    char path[256];    /* the field parser's limit; longer folders are not searched */
    gaudit_area_status status;
    int remote;
    int exact;
} gaudit_secret_area;

typedef enum {
    GAUDIT_SECRET_OWNER = 0,      /* only the owner */
    GAUDIT_SECRET_OWN_GROUP = 1,  /* the owner's own private group: counts as the owner */
    GAUDIT_SECRET_GROUP = 2,      /* members of other groups on the way */
    GAUDIT_SECRET_OTHERS = 3,     /* every account on the machine */
    GAUDIT_SECRET_REACHES
} gaudit_secret_reach;

typedef struct {
    unsigned area;     /* 0: the home folder */
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

int gaudit_secrets_format_area(const gaudit_secret_area *a, char *buf, size_t len);

/* One line, strictly: 1 a finding (in *f), 2 the summary (in *s), -1
 * anything else. An area line is 3, read with gaudit_secrets_parse_area. */
int gaudit_secrets_parse_line(const char *line, gaudit_secret_finding *f, gaudit_secrets_summary *s);

/* An area line, strictly: 0 (in *a), -1 anything else. */
int gaudit_secrets_parse_area(const char *line, gaudit_secret_area *a);

/* The verdict is the rule script's (rules/report.scm), nowhere else. */

#ifdef __cplusplus
}
#endif
