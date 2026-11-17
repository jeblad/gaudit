/* SPDX-License-Identifier: GPL-3.0-only */
/* gAudit checking itself (the helper's self-check, selfcheck.h): its row
 * under "This computer" on Home, at Thorough, and the page it leads to,
 * which says what was found and what it can mean. Presentation only. */
#pragma once

#include <adwaita.h>

#include "gaudit-session.h"

G_BEGIN_DECLS

/* The run command, and the id its finding has in the model. */
#define GAUDIT_SELF_COMMAND "run self-check"
#define GAUDIT_SELF_ID      "core.self"

/* A developer build with no signed list to compare with, and nothing else
 * found: the files' check does not apply, so it is neither counted nor
 * shown as unknown. Always FALSE outside developer builds. */
gboolean gaudit_self_not_applicable(const GauditRunResult *r);

/* Its icon: information, labelled "Does not apply". */
GtkWidget *gaudit_self_not_applicable_icon_new(void);

/* What was found, in a few words, for Home's row. */
char *gaudit_self_title(const GauditRunResult *r);

/* The page with the findings; when: the time it was checked ("14:32"). */
AdwNavigationPage *gaudit_self_page_new(const GauditRunResult *r, const char *when);

G_END_DECLS
