/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit-crossfade.h"

struct _GauditCrossfade {
    GObject parent_instance;
    GdkPaintable *from;
    GdkPaintable *to;
    double progress;  /* 0: only from, 1: only to */
    AdwAnimation *animation;
};

static void paintable_iface_init(GdkPaintableInterface *iface);
static void symbolic_iface_init(GtkSymbolicPaintableInterface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE(GauditCrossfade, gaudit_crossfade, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(GDK_TYPE_PAINTABLE, paintable_iface_init)
    G_IMPLEMENT_INTERFACE(GTK_TYPE_SYMBOLIC_PAINTABLE, symbolic_iface_init))

static void draw(GdkPaintable *p, GdkSnapshot *snapshot, double width, double height,
                 const GdkRGBA *colors, gsize n_colors, double opacity)
{
    if (p == NULL || opacity <= 0.0)
        return;
    gtk_snapshot_push_opacity(snapshot, opacity);
    if (colors != NULL && GTK_IS_SYMBOLIC_PAINTABLE(p))
        gtk_symbolic_paintable_snapshot_symbolic(GTK_SYMBOLIC_PAINTABLE(p), snapshot,
                                                 width, height, colors, n_colors);
    else
        gdk_paintable_snapshot(p, snapshot, width, height);
    gtk_snapshot_pop(snapshot);
}

static void snapshot_symbolic(GtkSymbolicPaintable *paintable, GdkSnapshot *snapshot,
                              double width, double height, const GdkRGBA *colors, gsize n_colors)
{
    GauditCrossfade *self = GAUDIT_CROSSFADE(paintable);
    draw(self->from, snapshot, width, height, colors, n_colors, 1.0 - self->progress);
    draw(self->to, snapshot, width, height, colors, n_colors, self->progress);
}

static void snapshot(GdkPaintable *paintable, GdkSnapshot *snapshot, double width, double height)
{
    GauditCrossfade *self = GAUDIT_CROSSFADE(paintable);
    draw(self->from, snapshot, width, height, NULL, 0, 1.0 - self->progress);
    draw(self->to, snapshot, width, height, NULL, 0, self->progress);
}

static int intrinsic_width(GdkPaintable *paintable)
{
    GauditCrossfade *self = GAUDIT_CROSSFADE(paintable);
    return self->to != NULL ? gdk_paintable_get_intrinsic_width(self->to) : 0;
}

static int intrinsic_height(GdkPaintable *paintable)
{
    GauditCrossfade *self = GAUDIT_CROSSFADE(paintable);
    return self->to != NULL ? gdk_paintable_get_intrinsic_height(self->to) : 0;
}

static void paintable_iface_init(GdkPaintableInterface *iface)
{
    iface->snapshot = snapshot;
    iface->get_intrinsic_width = intrinsic_width;
    iface->get_intrinsic_height = intrinsic_height;
}

static void symbolic_iface_init(GtkSymbolicPaintableInterface *iface)
{
    iface->snapshot_symbolic = snapshot_symbolic;
}

static void on_step(double value, gpointer data)
{
    GauditCrossfade *self = data;
    self->progress = CLAMP(value, 0.0, 1.0);
    gdk_paintable_invalidate_contents(GDK_PAINTABLE(self));
}

static void gaudit_crossfade_dispose(GObject *object)
{
    GauditCrossfade *self = GAUDIT_CROSSFADE(object);
    /* The animation calls back into us: stop it before anything goes. */
    if (self->animation != NULL) {
        adw_animation_skip(self->animation);
        g_clear_object(&self->animation);
    }
    g_clear_object(&self->from);
    g_clear_object(&self->to);
    G_OBJECT_CLASS(gaudit_crossfade_parent_class)->dispose(object);
}

static void gaudit_crossfade_class_init(GauditCrossfadeClass *klass)
{
    G_OBJECT_CLASS(klass)->dispose = gaudit_crossfade_dispose;
}

static void gaudit_crossfade_init(GauditCrossfade *self)
{
    (void)self;
}

static GdkPaintable *lookup(GtkWidget *widget, const char *name, int size)
{
    GtkIconTheme *theme = gtk_icon_theme_get_for_display(gtk_widget_get_display(widget));
    return GDK_PAINTABLE(gtk_icon_theme_lookup_icon(theme, name, NULL, size,
                                                    gtk_widget_get_scale_factor(widget),
                                                    gtk_widget_get_direction(widget), 0));
}

GdkPaintable *gaudit_crossfade_new(GtkWidget *widget, const char *from, const char *to,
                                   int size, guint duration)
{
    g_return_val_if_fail(GTK_IS_WIDGET(widget) && from != NULL && to != NULL, NULL);
    GauditCrossfade *self = g_object_new(GAUDIT_TYPE_CROSSFADE, NULL);
    self->from = lookup(widget, from, size);
    self->to = lookup(widget, to, size);
    AdwAnimationTarget *target = adw_callback_animation_target_new(on_step, self, NULL);
    self->animation = adw_timed_animation_new(widget, 0.0, 1.0, duration, target);
    adw_timed_animation_set_easing(ADW_TIMED_ANIMATION(self->animation), ADW_EASE_IN_OUT_CUBIC);
    adw_animation_play(self->animation);
    return GDK_PAINTABLE(self);
}
