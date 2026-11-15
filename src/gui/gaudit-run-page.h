/* SPDX-License-Identifier: GPL-3.0-only */
/* Page 2 for a task: starts the run through the orchestrator, shows its
 * progress and then the result. The run goes on if the page is left. */
#pragma once

#include <adwaita.h>

#include "gaudit-session.h"
#include "gaudit-task.h"

G_BEGIN_DECLS

AdwNavigationPage *gaudit_run_page_new(const GauditTaskInfo *task);

/* The run that made the task's cached collection, again with the same
 * parameters (Home's simplified one stays simplified); without a cache,
 * the full run with the parameters as they are now. For Reload. */
AdwNavigationPage *gaudit_run_page_again(const GauditTaskInfo *task);

/* Page 2 for the task's run under way (Home's, or a full one), showing its
 * result when it is done; NULL when none runs. */
AdwNavigationPage *gaudit_run_page_follow(const GauditTaskInfo *task);

/* The report from the task's cached collection, without collecting again.
 * NULL if nothing is cached. */
AdwNavigationPage *gaudit_cached_report_page_new(const GauditTaskInfo *task);

/* A result in one translated line, e.g. "No changed package files found".
 * Free with g_free. */
char *gaudit_run_result_title(const GauditRunResult *result);

G_END_DECLS
