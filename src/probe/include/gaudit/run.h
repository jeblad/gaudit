/* SPDX-License-Identifier: GPL-3.0-only */
/* A run on request (page 2), between orchestrator and GUI: one line per
 * event, language-neutral, parsed strictly on the receiving side.
 *
 *   (elevated (on 1))   the helper runs as root; (on 0) when it has ended
 *   (firewall ...)      the firewall result
 *   (integrity-file ...) one finding of the package integrity check (at most
 *                       GAUDIT_INTEGRITY_SHOWN, before the result)
 *   (integrity ...)     the package integrity result
 *   (exec (op "...") (status N))  a system tool run on request (apt): the
 *                       operation's name and its exit status
 *   (conf ...)          what writing a configuration did: its template, the
 *                       action (on, remove) and the result (conf-write.h's
 *                       names: written, unchanged, removed, not-there,
 *                       foreign, edited, precondition, unsafe, error)
 *   (vendor (id "...") (action A) (result R) (version "...") (hash "..."))
 *                       a known vendor package checked (A verify) or
 *                       installed (A install) on request; R one of
 *                       gaudit_vendor_result_known's names, hash the
 *                       signature's hash algorithm ("SHA1", "SHA256")
 *   (self-file (path "...") (problem "changed|missing|extra"))
 *   (self-process (which "orchestrator|gui") (problem "exe|env|maps|gone")
 *                 (detail "..."))
 *   (self (manifest "S") (version N) (files N) (changed N) (missing N) (extra N)
 *         (files-shown N) (processes N) (process-problems N) (processes-shown N))
 *                       gAudit checking itself in the helper (selfcheck.h):
 *                       the findings it lists (at most GAUDIT_SELF_SHOWN
 *                       of each), then the result; S one of
 *                       gaudit_self_manifest_known's names
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
    unsigned listening;     /* services listening for the network (the orchestrator's count) */
} gaudit_firewall_report;

/* The package integrity check: every deb package's files against dpkg's
 * md5sums (see the helper). */
typedef struct {
    gaudit_verdict verdict;
    unsigned long packages;
    unsigned long files;        /* in the md5sums lists */
    unsigned long checked;      /* read and compared */
    unsigned long changed;
    unsigned long missing;
    unsigned long unreadable;
    unsigned long excluded;     /* missing, but kept out by dpkg's path-exclude */
    unsigned long diverted;     /* skipped: moved aside with dpkg-divert */
    unsigned long bad_lines;    /* malformed lines in the md5sums lists */
    unsigned long megabytes;    /* read */
    unsigned shown;             /* findings listed before the result */
    unsigned seconds;
} gaudit_integrity_report;

#define GAUDIT_INTEGRITY_SHOWN 40

typedef enum {
    GAUDIT_INTEGRITY_FILE_CHANGED = 0,
    GAUDIT_INTEGRITY_FILE_MISSING = 1,
    GAUDIT_INTEGRITY_FILE_UNREADABLE = 2,
} gaudit_integrity_file_kind;

typedef struct {
    gaudit_integrity_file_kind kind;
    char package[128];
    char path[256];
} gaudit_integrity_file;

typedef struct {
    char template_id[64];
    char action[16];
    char result[16];
} gaudit_conf_report;

typedef struct {
    char op[32];
    int status;   /* the tool's exit status, 0 success; 255 could not be run */
} gaudit_exec_report;

typedef struct {
    char id[32];
    char action[16];   /* "verify" or "install" */
    char result[24];
    char version[40];
    char hash[16];
} gaudit_vendor_report;

/* gAudit checking itself: the signed manifest, its files, the processes
 * that asked. */
#define GAUDIT_SELF_SHOWN 40

typedef struct {
    char manifest[16];          /* ok, bad-signature, bad-format, expired, too-old,
                                   from-future, missing (none installed), no-key
                                   (a build without gAudit's key) */
    unsigned long long version;
    unsigned files, changed, missing, extra, files_shown;
    unsigned processes, process_problems, processes_shown;
} gaudit_self_report;

typedef struct {
    char path[256];
    char problem[8];            /* changed, missing, extra */
} gaudit_self_file;

typedef struct {
    char which[16];             /* orchestrator, gui */
    char problem[8];            /* exe, env, maps, gone */
    char detail[256];           /* the program, the variable or the file */
} gaudit_self_process;

/* 1 if name is one of the manifest states above. */
int gaudit_self_manifest_known(const char *name);

/* The verdict: a file that differs, is missing or is extra, a process not
 * as it should be, or a manifest that is not good (not signed by gAudit's
 * key, unreadable, older than one seen, from the future, expired) is a
 * warning; no manifest to check with (none installed, a build without
 * the key) leaves it unknown; otherwise OK. */
gaudit_verdict gaudit_self_verdict(const gaudit_self_report *r);

/* 1 if result is one of the names checking or installing a vendor
 * package can give: verified, weak (verified, but the signature's hash is
 * weaker than expected), installed, and the refusals no-file, too-large,
 * not-signed, unknown-key, bad-signature, weak-md5, mismatch,
 * wrong-package, not-newer, not-verified, failed, error. */
int gaudit_vendor_result_known(const char *result);

/* 1 if result is one of the names a configuration write can give. */
int gaudit_conf_result_known(const char *result);

typedef enum {
    GAUDIT_RUN_EVENT_ELEVATED,
    GAUDIT_RUN_EVENT_FIREWALL,
    GAUDIT_RUN_EVENT_INTEGRITY_FILE,
    GAUDIT_RUN_EVENT_INTEGRITY,
    GAUDIT_RUN_EVENT_CONF,
    GAUDIT_RUN_EVENT_EXEC,
    GAUDIT_RUN_EVENT_VENDOR,
    GAUDIT_RUN_EVENT_SELF_FILE,
    GAUDIT_RUN_EVENT_SELF_PROCESS,
    GAUDIT_RUN_EVENT_SELF,
    GAUDIT_RUN_EVENT_END,
} gaudit_run_event_type;

typedef struct {
    gaudit_run_event_type type;
    int elevated;                       /* _ELEVATED */
    gaudit_firewall_report firewall;    /* _FIREWALL */
    gaudit_integrity_file file;         /* _INTEGRITY_FILE */
    gaudit_integrity_report integrity;  /* _INTEGRITY */
    gaudit_conf_report conf;            /* _CONF */
    gaudit_exec_report exec;            /* _EXEC */
    gaudit_vendor_report vendor;        /* _VENDOR */
    gaudit_self_file self_file;         /* _SELF_FILE */
    gaudit_self_process self_process;   /* _SELF_PROCESS */
    gaudit_self_report self;            /* _SELF */
    gaudit_run_status status;           /* _END */
} gaudit_run_event;

/* The verdict for an integrity result: a changed file is a warning (it
 * may be harmless, but nothing should change installed files), a missing
 * one too; nothing found is OK. Files that could not be read, or
 * malformed lists, make it unknown when nothing worse was found. */
gaudit_verdict gaudit_integrity_verdict(const gaudit_integrity_report *r);

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
