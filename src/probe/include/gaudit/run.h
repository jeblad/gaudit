/* SPDX-License-Identifier: GPL-3.0-only */
/* A run on request (page 2), between orchestrator and GUI: one line per
 * event, language-neutral, parsed strictly on the receiving side.
 *
 *   (elevated (on 1))   the helper runs as root; (on 0) when it has ended
 *   (firewall ...)      the firewall result
 *   (end (status S))    always last; S is a gaudit_run_status */
#pragma once

#include <stddef.h>

#include "gaudit/model.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GAUDIT_RUN_OK = 0,
    GAUDIT_RUN_CANCELLED = 1,  /* the password dialog was dismissed */
    GAUDIT_RUN_DENIED = 2,     /* not authorized (wrong password, policy) */
    GAUDIT_RUN_FAILED = 3,     /* the helper or its check failed */
} gaudit_run_status;

typedef struct {
    gaudit_verdict verdict;
    unsigned tables;
    unsigned input_chains;  /* filter chains on the input hook */
    unsigned input_drop;    /* ... with policy drop */
    unsigned input_rules;   /* rules in those chains */
    unsigned rules;         /* rules in every chain */
    unsigned legacy;        /* legacy iptables tables loaded (not visible in nftables) */
} gaudit_firewall_report;

typedef enum {
    GAUDIT_RUN_EVENT_ELEVATED,
    GAUDIT_RUN_EVENT_FIREWALL,
    GAUDIT_RUN_EVENT_END,
} gaudit_run_event_type;

typedef struct {
    gaudit_run_event_type type;
    int elevated;                     /* _ELEVATED */
    gaudit_firewall_report firewall;  /* _FIREWALL */
    gaudit_run_status status;         /* _END */
} gaudit_run_event;

/* The firewall's verdict from what the helper found. Interim, in C, until
 * the rule engine takes over: incoming traffic must meet a filter chain
 * that drops by default or has rules. Legacy iptables tables hide their
 * rules from nftables, so with no nftables input filter the answer is
 * then unknown, not a warning. */
gaudit_verdict gaudit_firewall_verdict(const gaudit_firewall_report *r);

/* One event as a newline-terminated line. 0 on success, -1 if it does not
 * fit. */
int gaudit_run_format(const gaudit_run_event *ev, char *buf, size_t len);

/* Strict parser for one line (with or without the newline). 0 on
 * success, -1 otherwise. */
int gaudit_run_parse_line(const char *line, gaudit_run_event *out);

#ifdef __cplusplus
}
#endif
