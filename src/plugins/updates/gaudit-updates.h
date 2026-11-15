/* SPDX-License-Identifier: GPL-3.0-only */
/* Updates in the GUI: checking its collection's lines, and the fix pages
 * its report leads to. Texts are in the plugin's own text domain. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_UPDATES_DOMAIN "gaudit-updates"

/* One line of "gaudit-orchestrator updates", strictly; *last for the
 * closing count. */
gboolean gaudit_updates_line(const char *line, gboolean *last);

/* The fix the report names for the fact at item in lines (the cached
 * collection, which also names the backend). */
AdwNavigationPage *gaudit_updates_fix_page(const char *fix_id, GPtrArray *lines, guint item);

G_END_DECLS
