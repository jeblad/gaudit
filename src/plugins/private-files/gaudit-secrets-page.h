/* SPDX-License-Identifier: GPL-3.0-only */
/* Private Files: presenting the deep scan's result on page 2. */
#pragma once

#include <adwaita.h>

#include "gaudit-session.h"

G_BEGIN_DECLS

/* The result in one translated line. Free with g_free. */
char *gaudit_secrets_title(const GauditRunResult *result);

/* Fills status (page 2) with the result: the verdict, then the findings by
 * who can reach them, and the manual way to close them. */
void gaudit_secrets_show(AdwStatusPage *status, const GauditRunResult *result);

G_END_DECLS
