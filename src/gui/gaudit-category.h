/* SPDX-License-Identifier: GPL-3.0-only */
/* Categories of tools (firewall, antivirus) and Home's page for a category
 * with nothing installed: the known tools, what each is, how to install
 * it, and the distribution's usual choice marked as recommended. Which
 * tools exist and what they are is presentation; package names and the
 * install command come from the backend's fixed table. */
#pragma once

#include <adwaita.h>

#include "gaudit/backend.h"

G_BEGIN_DECLS

typedef struct {
    const char *capability;   /* resolved by the backend */
    const char *name;         /* N_() */
    const char *description;  /* N_() */
    const char *enable;       /* command that switches it on after installing; NULL if it
                                 needs none. Fixed, never built from the system. */
} GauditCategoryTool;

typedef struct {
    const char *probe_id;     /* the Home row that reports the category, e.g. "status.firewall" */
    const char *title;        /* the page's title, N_() */
    const char *intro;        /* N_() */
    const GauditCategoryTool *tools;
    gsize n_tools;
} GauditCategory;

/* The category a Home row reports on; NULL for none. */
const GauditCategory *gaudit_category_for_probe(const char *probe_id);

/* The enable command of the first tool of the category that is installed;
 * NULL if none is, or it needs none. */
const char *gaudit_category_enable_command(const GauditCategory *category,
                                           const gaudit_pkg_backend *pkg);

AdwNavigationPage *gaudit_category_page_new(const GauditCategory *category,
                                            const gaudit_pkg_backend *pkg);

G_END_DECLS
