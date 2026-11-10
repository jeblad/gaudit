/* SPDX-License-Identifier: GPL-3.0-only */
/* Home's page 2 for packages without a source: the list, in three groups,
 * the one that gets no updates first. Fetched from the orchestrator. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

AdwNavigationPage *gaudit_sourceless_page_new(void);

G_END_DECLS
