/* SPDX-License-Identifier: GPL-3.0-only */
/* Status probes: what can be found out without elevated privileges and
 * without starting a full run. Results are language-neutral; the GUI turns
 * them into text. */
#pragma once

#include <stdint.h>

#include "gaudit/backend.h"
#include "gaudit/model.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Also the display order on Home. */
typedef enum {
    GAUDIT_PROBE_PACKAGE_SYSTEM = 0, /* the package system the distribution implies is present */
    GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS, /* package systems present that are not checked */
    GAUDIT_PROBE_ANTIVIRUS,         /* some known antivirus program is installed */
    GAUDIT_PROBE_FIREWALL,          /* some known firewall is installed */
    GAUDIT_PROBE_LISTENING,         /* services listening for the network (informs only) */
    GAUDIT_PROBE_AUTO_UPDATES,      /* updates are installed automatically */
    GAUDIT_PROBE_SECURITY_SOURCE,   /* security updates come from the distribution itself */
    GAUDIT_PROBE_PRIVATE_FILES,     /* private files in the home directory are protected */
    GAUDIT_PROBE_PACKAGE_INDEX,     /* when updates were last checked for */
    GAUDIT_PROBE_PENDING_UPGRADES,  /* updates waiting to be installed */
    GAUDIT_PROBE_OBSOLETE_PACKAGES, /* packages no software source offers */
    GAUDIT_PROBE_FLATPAK,           /* Flatpak apps on end-of-life runtimes */
    GAUDIT_PROBE_SNAP,              /* snaps that are not kept up to date or unconfined */
    GAUDIT_PROBE_COUNT
} gaudit_probe_kind;

/* Snaps not refreshed automatically for longer than this is a warning. */
#define GAUDIT_PROBE_SNAP_MAX_AGE (7 * 24 * 60 * 60)

/* Package index older than this is a warning. */
#define GAUDIT_PROBE_INDEX_MAX_AGE (7 * 24 * 60 * 60)

typedef struct {
    gaudit_probe_kind kind;
    const char *id;           /* stable key, e.g. "status.firewall" (static; from the kind) */
    gaudit_verdict verdict;
    int64_t age_seconds;      /* GAUDIT_PROBE_PACKAGE_INDEX */
    unsigned count;           /* _PENDING_UPGRADES, _OBSOLETE_PACKAGES; _FLATPAK: eol apps;
                                 _LISTENING: services, extra_count: of those the user's own */
    unsigned extra_count;     /* _FLATPAK: unused end-of-life refs */
    unsigned info_count;      /* _FLATPAK: end-of-life runtimes kept (pinned) but unused */
    int applicable;           /* 0: does not apply here (e.g. no Flatpak), not shown */
    char missing_capability[32];  /* set ("" otherwise) when software for the check is missing */
    int unsupported;          /* 1: this check is not supported on this system (yet) */
    char detail[32];          /* _PACKAGE_SYSTEM: the expected package system, e.g. "dpkg/apt" */
    unsigned mask;            /* _OTHER_PACKAGE_SYSTEMS: 1 << gaudit_package_system */
    int64_t until_epoch;      /* _SNAP: automatic refreshes held until then (0: not held) */
    int service_down;         /* _SNAP: snapd did not answer */
    char text[64];            /* _SECURITY_SOURCE: the mirror's host name;
                                 _PRIVATE_FILES: the first problem ("~/..."), count in count */
    /* _SNAP also uses count (devmode), extra_count (held), info_count
     * (classic, informs only) and age_seconds (since the last refresh, -1 unknown). */
} gaudit_probe_result;

/* Fills out[kind] for every kind. now: seconds since epoch. */
void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

/* As above. expected: the backend the distribution implies (may be NULL).
 * If it differs from pkg, the expected package system was not found:
 * GAUDIT_PROBE_PACKAGE_SYSTEM becomes a warning. Otherwise that row does
 * not apply (the Home heading already says what was found). */
void gaudit_probe_collect_ex(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                             int64_t now, gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

/* Every kind with its default: unknown, shown; the package system rows
 * not shown. What a kind keeps when its task could not run. */
void gaudit_probe_init(gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

/* The probes in independent tasks, so they can run side by side (the
 * orchestrator runs each in its own process) and a slow one does not hold
 * up the rest. A task may fill several kinds. */
#define GAUDIT_PROBE_TASK_COUNT 10

/* The kinds a task fills, as 1 << kind; 0 for an unknown task. */
unsigned gaudit_probe_task_kinds(int task);

/* Runs one task and fills its kinds in out (initialised with
 * gaudit_probe_init). Arguments as for gaudit_probe_collect_ex. */
void gaudit_probe_run_task(int task, const gaudit_pkg_backend *pkg,
                           const gaudit_pkg_backend *expected, int64_t now,
                           gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

/* Stable key for a kind, e.g. "status.firewall"; NULL for an unknown kind. */
const char *gaudit_probe_id(gaudit_probe_kind kind);

/* One result as a single line S-expression, newline-terminated, for the
 * pipe between orchestrator and GUI. 0 on success, -1 if it does not fit. */
int gaudit_probe_format(const gaudit_probe_result *r, char *buf, size_t len);

/* Strict parser for one line of the orchestrator's output (with or without
 * the newline). 0 on success, -1 otherwise. */
int gaudit_probe_parse_line(const char *line, gaudit_probe_result *out);

/* Strict parser for the orchestrator's output: one line per kind, every
 * kind exactly once, nothing else. ids are filled in from the kinds.
 * 0 on success, -1 otherwise (out is then unspecified). */
int gaudit_probe_parse_all(const char *text, gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

#ifdef __cplusplus
}
#endif
