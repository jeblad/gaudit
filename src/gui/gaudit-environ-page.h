/* SPDX-License-Identifier: GPL-3.0-only */
/* The variables that load code, removed before the program opened
 * (gaudit-environ.h): its row under "This computer" on Home, and the page
 * it leads to, which says what each one pointed to, who can change that,
 * and what the user can do. Presentation only. */
#pragma once

#include <adwaita.h>

#include "gaudit/model.h"

G_BEGIN_DECLS

/* WARNING when any of them points to something others than the
 * administrator can change; OK when all point only to the administrator's
 * folders (or load nothing); UNKNOWN when none were removed. */
gaudit_verdict gaudit_environ_verdict(void);

/* The page. */
AdwNavigationPage *gaudit_environ_page_new(void);

G_END_DECLS
