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
    GAUDIT_PROBE_ANTIVIRUS = 0,     /* some known antivirus program is installed */
    GAUDIT_PROBE_FIREWALL,          /* some known firewall is installed */
    GAUDIT_PROBE_AUTO_UPDATES,      /* updates are installed automatically */
    GAUDIT_PROBE_PACKAGE_INDEX,     /* when updates were last checked for */
    GAUDIT_PROBE_PENDING_UPGRADES,  /* updates waiting to be installed */
    GAUDIT_PROBE_OBSOLETE_PACKAGES, /* packages no software source offers */
    GAUDIT_PROBE_FLATPAK,           /* Flatpak apps on end-of-life runtimes */
    GAUDIT_PROBE_COUNT
} gaudit_probe_kind;

/* Package index older than this is a warning. */
#define GAUDIT_PROBE_INDEX_MAX_AGE (7 * 24 * 60 * 60)

typedef struct {
    gaudit_probe_kind kind;
    const char *id;           /* stable key, e.g. "status.firewall" */
    gaudit_verdict verdict;
    int64_t age_seconds;      /* GAUDIT_PROBE_PACKAGE_INDEX */
    unsigned count;           /* _PENDING_UPGRADES, _OBSOLETE_PACKAGES; _FLATPAK: eol apps */
    unsigned extra_count;     /* _FLATPAK: unused end-of-life refs */
    unsigned info_count;      /* _FLATPAK: end-of-life runtimes kept (pinned) but unused */
    int applicable;           /* 0: does not apply here (e.g. no Flatpak), not shown */
    const char *missing_capability;  /* set when software for the check is missing */
    int unsupported;          /* 1: this check is not supported on this system (yet) */
} gaudit_probe_result;

/* Fills out[kind] for every kind. now: seconds since epoch. */
void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT]);

#ifdef __cplusplus
}
#endif
