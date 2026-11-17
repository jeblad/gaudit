/* SPDX-License-Identifier: GPL-3.0-only */
/* gAudit checking itself, from the helper, the one part that cannot be
 * checked by another and so is the anchor (a binary cannot verify itself).
 * It checks the signed manifest (manifest.h), every file it lists, the
 * files in gAudit's own folders it does not list, and the processes that
 * asked for it: the orchestrator and the GUI, that each runs the program
 * it should, with no variable that loads other code (gaudit-environ.h),
 * and no executable code from outside the system's folders. It reports;
 * it changes nothing but the record of the highest manifest version seen.
 *
 *   (self-file (path "...") (problem "changed|missing|extra"))         at most 40
 *   (self-process (which "orchestrator|gui") (problem "exe|env|maps|gone") (detail "..."))
 *                                                                      at most 40
 *   (self (manifest "S") (version N) (files N) (changed N) (missing N) (extra N)
 *         (files-shown N) (processes N) (process-problems N) (processes-shown N))
 *
 * The same lines as the run events of gaudit/run.h, so the orchestrator
 * reads them with its strict parser.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "manifest.h"

typedef struct {
    const char *manifest_path, *sig_path;
    const gaudit_manifest_key *keys;
    size_t n_keys;
    unsigned long long min_version;   /* the built-in lowest allowed */
    const char *state_file;           /* the highest version seen; root's, e.g. /var/lib/gaudit/manifest-version */
    const char *const *dirs;          /* gAudit's own folders: every file in them must be listed */
    size_t n_dirs;
    pid_t orchestrator;               /* who asked (the helper's parent); its parent is the GUI */
    const char *orchestrator_exe, *gui_exe;  /* the programs they must be */
    const char *const *code_dirs;     /* where executable code may come from ("/usr/", ...) */
    size_t n_code_dirs;
    int developer;                    /* a developer build: its own programs are not root's */
    int64_t now;
} gaudit_selfcheck_env;

/* Runs the whole check and writes its lines to out. */
void gaudit_selfcheck(const gaudit_selfcheck_env *env, FILE *out);

/* The checks of one process, for tests: the problems found (0 none), each
 * written to out as a self-process line for which. */
int gaudit_selfcheck_process(const gaudit_selfcheck_env *env, pid_t pid, const char *which,
                             const char *exe, FILE *out);
