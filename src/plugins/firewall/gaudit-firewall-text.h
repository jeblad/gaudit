/* SPDX-License-Identifier: GPL-3.0-only */
/* What a firewall result means, in words: shared by page 2 and the row
 * on Home, so both say the same. */
#pragma once

#include <glib.h>

#include "gaudit/run.h"

G_BEGIN_DECLS

/* icon: static; title and description: newly allocated. */
void gaudit_firewall_text(const gaudit_firewall_report *f, const char **icon,
                          char **title, char **description);

G_END_DECLS
