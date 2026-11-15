/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates collection: facts about how updates reach this system,
 * never judgements (those are in rules/report.scm). One line per fact,
 * each key at most once, then a closing line with the count:
 *
 *   (fact (key "check-days") (status S) (value N) (text "..."))
 *   (facts (count N))
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
    GAUDIT_UPDATE_INDEX_AGE,        /* seconds since updates were last looked for */
    GAUDIT_UPDATE_PENDING,          /* updates waiting to be installed */
    GAUDIT_UPDATE_PENDING_SECURITY, /* of those, security updates */
    GAUDIT_UPDATE_SECURITY_OFFICIAL, /* security sources from the distribution itself */
    GAUDIT_UPDATE_SECURITY_MIRROR,  /* security sources from a mirror; text: the first host */
    GAUDIT_UPDATE_SOURCELESS,       /* installed packages no source offers */
    GAUDIT_UPDATE_SOURCELESS_ABOVE, /* of those, newer than the source */
    GAUDIT_UPDATE_SOURCELESS_LEFTOVER, /* probably left over from an older release */
    GAUDIT_UPDATE_SOURCELESS_OTHER, /* probably from other places */
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

/* "check-days" and so on; NULL for an unknown key. */
const char *gaudit_update_key_name(gaudit_update_key key);

/* One line, newline-terminated. 0 on success. */
int gaudit_update_format_fact(const gaudit_update_fact *f, char *buf, size_t len);
int gaudit_update_format_end(unsigned count, char *buf, size_t len);

/* Strict parser for one line (with or without the newline):
 * 1 a fact (into *fact), 2 the closing line (into *count), -1 otherwise. */
int gaudit_update_parse_line(const char *line, gaudit_update_fact *fact, unsigned *count);
