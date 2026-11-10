/* SPDX-License-Identifier: GPL-3.0-only */
/* A paintable that fades from one icon to another, e.g. Home's shield
 * from "the simple checks passed" to "every check passed". Symbolic icons
 * keep their recolouring. The fade is skipped when animations are off. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_TYPE_CROSSFADE (gaudit_crossfade_get_type())
G_DECLARE_FINAL_TYPE(GauditCrossfade, gaudit_crossfade, GAUDIT, CROSSFADE, GObject)

/* Fades from icon `from` to icon `to` (theme names) at `size` pixels, over
 * `duration` ms, starting at once. `widget` shows the result. */
GdkPaintable *gaudit_crossfade_new(GtkWidget *widget, const char *from, const char *to,
                                   int size, guint duration);

G_END_DECLS
