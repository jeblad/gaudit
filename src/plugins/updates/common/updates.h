/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates collection: facts about how updates reach this system,
 * never judgements (those are in rules/report.scm). One line per fact,
 * each key at most once, then a closing line with the count:
 *
 *   (fact (key "check-days") (status S) (value N) (text "..."))
 *   (vendor-package (id "zoom") (title "Zoom") (vendor "Zoom") (version "..."))
 *   (facts (count N))
 *
 * A vendor-package line per known vendor package installed (vendor.h), at
 * most GAUDIT_UPDATE_MAX_VENDOR, after the facts; count is the facts only.
 *
 * A vendor-local line per local copy of a vendor's source found (vendor.h),
 * at most GAUDIT_UPDATE_MAX_VENDOR, also after the facts:
 *
 *   (vendor-local (id "cuda") (title "CUDA") (vendor "NVIDIA") (version "13.3")
 *                 (made-for "ubuntu2604") (made-for-name "Ubuntu 26.04")
 *                 (running "ubuntu2610") (previous "ubuntu2604") (packages N))
 *
 * packages: those installed with the very name and version the copy
 * lists; previous: the release before the one running ("" none known).
 *
 * A vendor-companion line per package another program keeps up to date
 * (vendor.h), at most GAUDIT_UPDATE_MAX_VENDOR, after the facts:
 *
 *   (vendor-companion (id "clamui-helper") (package "...") (manager "ClamUI")
 *                     (version "...") (present 0|1))
 *
 * present: the program that manages it is installed.
 *
 * "updates latest <id>" (on request, from the package's page) writes one
 * line, which the GUI adds to the cached collection:
 *
 *   (vendor-latest (id "zoom") (status S) (version "...") (installed "...") (newer N))
 *
 * status 0 found out, 1 not; newer 1 when version is newer than installed.
 *
 * "updates download <id> <version>" writes one line:
 *
 *   (vendor-download (id "zoom") (status S) (path "...") (reason "..."))
 *
 * status 0 downloaded to path, 1 not (path ""); reason "" when it was,
 * else where it stopped: folder, no-fetcher, fetch-<exit code>, size, rename.
 *
 * status: 0 known, 1 could not be found out, 2 not supported on this
 * system, 3 does not apply here. value and text are 0 and "" where a key
 * has none. The keys (gaudit_update_key) are a fixed list. */
#pragma once

#include <stddef.h>

typedef enum {
    GAUDIT_UPDATE_BACKEND = 0,      /* text: the backend's name ("debian") */
    GAUDIT_UPDATE_EXPECTED_MISSING, /* value 1: the package system the distribution implies
                                       is missing; text: it ("dpkg/apt") */
    GAUDIT_UPDATE_OTHER_SYSTEMS,    /* value: how many other package systems have packages;
                                       text: their names, ", " between */
    GAUDIT_UPDATE_CHECK_DAYS,       /* days between looking for updates, 0 never */
    GAUDIT_UPDATE_INSTALL,          /* 1: installed automatically */
    GAUDIT_UPDATE_DOWNLOAD,         /* 1: downloaded automatically */
    GAUDIT_UPDATE_CHECK_TIMER,      /* 1: the timer that looks for updates is on */
    GAUDIT_UPDATE_INSTALL_TIMER,    /* 1: the timer that installs them is on */
    GAUDIT_UPDATE_LAST_INSTALL,     /* seconds since updates were last installed
                                       automatically, -1 never */
    GAUDIT_UPDATE_LAST_CHANGE,      /* seconds since packages were last installed or
                                       updated, by any means */
    GAUDIT_UPDATE_ADMIN_TOOLS,      /* admin tools installed that can set updates up;
                                       text: their package names */
    GAUDIT_UPDATE_OWN_SETTING,      /* 1: gAudit's own drop-in for automatic updates is there */
    GAUDIT_UPDATE_UPGRADE_UPDATES,  /* 1: the upgrade command can fetch the lists itself */
    GAUDIT_UPDATE_UNREAD_SOURCES,   /* software sources set up but never read; text: their hosts */
    GAUDIT_UPDATE_UPGRADE_OFF,      /* sources switched off when the release was upgraded;
                                       text: their names */
    GAUDIT_UPDATE_INDEX_AGE,        /* seconds since updates were last looked for */
    GAUDIT_UPDATE_PENDING,          /* updates waiting to be installed */
    GAUDIT_UPDATE_PENDING_SECURITY, /* of those, security updates */
    GAUDIT_UPDATE_SECURITY_OFFICIAL, /* security sources from the distribution itself */
    GAUDIT_UPDATE_SECURITY_MIRROR,  /* security sources from a mirror; text: the first host */
    GAUDIT_UPDATE_SOURCELESS,       /* installed packages no source offers */
    GAUDIT_UPDATE_SOURCELESS_ABOVE, /* of those, newer than the source */
    GAUDIT_UPDATE_SOURCELESS_LEFTOVER, /* probably left over from an older release */
    GAUDIT_UPDATE_SOURCELESS_OTHER, /* probably from other places */
    GAUDIT_UPDATE_SOURCELESS_VENDOR, /* known vendor packages, not counted in the four above:
                                        each has a vendor-package line */
    GAUDIT_UPDATE_SOURCELESS_KEPT,  /* of SOURCELESS, updates kept from the release before;
                                       text: that release ("Ubuntu 26.04"), "" unknown */
    GAUDIT_UPDATE_KEYS
} gaudit_update_key;

typedef enum {
    GAUDIT_FACT_KNOWN = 0,
    GAUDIT_FACT_UNKNOWN,
    GAUDIT_FACT_UNSUPPORTED,
    GAUDIT_FACT_NOT_APPLICABLE,
} gaudit_fact_status;

typedef struct {
    gaudit_update_key key;
    gaudit_fact_status status;
    long long value;
    char text[128];
} gaudit_update_fact;

#define GAUDIT_UPDATE_MAX_VENDOR 16

/* A known vendor package installed: id, title and vendor from gAudit's
 * table, the version as the package database has it. */
typedef struct {
    char id[32];
    char title[64];
    char vendor[64];
    char version[96];
} gaudit_update_vendor;

/* A package another program keeps up to date. */
typedef struct {
    char id[32];
    char package[128];
    char manager[64];
    char version[96];
    int present;
} gaudit_update_companion;

int gaudit_update_format_companion(const gaudit_update_companion *c, char *buf, size_t len);
/* Strict parser: 0 with *c set, -1 otherwise. */
int gaudit_update_parse_companion(const char *line, gaudit_update_companion *c);

/* A local copy of a vendor's source, and how many installed packages came
 * from it. */
typedef struct {
    char id[32];
    char title[64];
    char vendor[64];
    char version[16];
    char made_for[16];
    char made_for_name[32];
    char running[16];
    char previous[16];
    unsigned packages;
} gaudit_update_local;

int gaudit_update_format_local(const gaudit_update_local *l, char *buf, size_t len);
/* Strict parser: 0 with *l set, -1 otherwise. */
int gaudit_update_parse_local(const char *line, gaudit_update_local *l);

/* The newest version the vendor offers, found out on request. */
typedef struct {
    char id[32];
    int status;          /* 0 found out, 1 not */
    char version[40];    /* the vendor's newest, "" when not found out */
    char installed[96];  /* the version installed */
    int newer;           /* 1: version is newer than installed */
} gaudit_update_latest;

typedef struct {
    char id[32];
    int status;          /* 0 downloaded, 1 not */
    char path[256];      /* the longest text the line parser takes */
    char reason[32];
} gaudit_update_download;

int gaudit_update_format_download(const gaudit_update_download *d, char *buf, size_t len);
/* Strict parser: 0 with *d set, -1 otherwise. */
int gaudit_update_parse_download(const char *line, gaudit_update_download *d);

int gaudit_update_format_latest(const gaudit_update_latest *l, char *buf, size_t len);
/* Strict parser: 0 with *l set, -1 otherwise. */
int gaudit_update_parse_latest(const char *line, gaudit_update_latest *l);

/* "check-days" and so on; NULL for an unknown key. */
const char *gaudit_update_key_name(gaudit_update_key key);

/* One line, newline-terminated. 0 on success. */
int gaudit_update_format_fact(const gaudit_update_fact *f, char *buf, size_t len);
int gaudit_update_format_end(unsigned count, char *buf, size_t len);
int gaudit_update_format_vendor(const gaudit_update_vendor *v, char *buf, size_t len);

/* Strict parser for a vendor-package line: 0 with *v set, -1 otherwise. */
int gaudit_update_parse_vendor(const char *line, gaudit_update_vendor *v);

/* Strict parser for one line (with or without the newline):
 * 1 a fact (into *fact), 2 the closing line (into *count), -1 otherwise. */
int gaudit_update_parse_line(const char *line, gaudit_update_fact *fact, unsigned *count);
