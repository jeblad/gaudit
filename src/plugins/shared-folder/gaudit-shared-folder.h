/* SPDX-License-Identifier: GPL-3.0-only */
/* Shared Folder in the GUI: checking its collection's lines, and the page
 * that tidies a duplicate. Texts are in the plugin's own text domain. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_SHARED_FOLDER_DOMAIN "gaudit-shared-folder"

/* One line of "gaudit-orchestrator shared", strictly; *last for the end. */
gboolean gaudit_shared_folder_line(const char *line, gboolean *last);

/* The fix the report names: "tidy" for the folder at item in lines. */
AdwNavigationPage *gaudit_shared_folder_fix_page(const char *fix_id, GPtrArray *lines, guint item);

G_END_DECLS
