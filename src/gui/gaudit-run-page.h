/* SPDX-License-Identifier: GPL-3.0-only */
/* Page 2 for a task: starts the run through the orchestrator, shows its
 * progress and then the result. The run goes on if the page is left. */
#pragma once

#include <adwaita.h>

#include "gaudit-task.h"

G_BEGIN_DECLS

AdwNavigationPage *gaudit_run_page_new(const GauditTaskInfo *task);

G_END_DECLS
