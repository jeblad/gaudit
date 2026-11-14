/* SPDX-License-Identifier: GPL-3.0-only */
/* Private Files in the GUI: checking its collection's lines, and the fix
 * pages its report leads to. Texts are in the plugin's own text domain. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_PRIVATE_FILES_DOMAIN "gaudit-private-files"

/* One line of "gaudit-orchestrator secrets", strictly; *last for the
 * summary, which ends the collection. */
gboolean gaudit_private_files_line(const char *line, gboolean *last);

/* The fix the report names for item_line (a finding of the collection). */
AdwNavigationPage *gaudit_private_files_fix_page(const char *fix_id, const char *item_line);

G_END_DECLS
