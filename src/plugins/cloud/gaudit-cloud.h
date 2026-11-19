/* SPDX-License-Identifier: GPL-3.0-only */
/* Cloud Services in the GUI: checking its collection's lines. It has no
 * fix pages: moving a cloud folder is done in its own program's settings. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_CLOUD_DOMAIN "gaudit-cloud"

/* One line of "gaudit-orchestrator cloud", strictly; *last for the end. */
gboolean gaudit_cloud_line_ok(const char *line, gboolean *last);

G_END_DECLS
