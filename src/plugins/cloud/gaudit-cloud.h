/* SPDX-License-Identifier: GPL-3.0-only */
/* Cloud Services in the GUI: checking its collection's lines, and the page
 * that helps set up a cloud service with rclone. No page of it moves
 * anything: a cloud folder is moved in its own program's settings. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_CLOUD_DOMAIN "gaudit-cloud"

/* One line of "gaudit-orchestrator cloud", strictly; *last for the end. */
gboolean gaudit_cloud_line_ok(const char *line, gboolean *last);

/* Setting a cloud service up with rclone: the plugin's own page in its
 * folder, after the report. */
AdwNavigationPage *gaudit_cloud_setup_page(void);

/* A report row's page, built from collection line item: "plain", files
 * outside the encrypted folder, and "names", names that look like secrets,
 * each with the button that asks the service; "secret-readable",
 * "secret-unclear" and "secret-own", one secret in a cloud folder. */
AdwNavigationPage *gaudit_cloud_fix_page(const char *fix_id, GPtrArray *lines, guint item);

G_END_DECLS
