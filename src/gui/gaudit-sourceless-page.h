/* SPDX-License-Identifier: GPL-3.0-only */
/* The packages without a source, fetched from the orchestrator. Each row
 * of the Updates report about them leads to its own page with only its
 * group, about that problem and nothing else. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

/* All three groups, the one that gets no updates first. */
AdwNavigationPage *gaudit_sourceless_page_new(void);

/* Only group (a gaudit_sourceless_group), titled by it. */
AdwNavigationPage *gaudit_sourceless_page_new_group(int group);

G_END_DECLS
