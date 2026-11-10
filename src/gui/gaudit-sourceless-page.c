/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-orchestrator.h"
#include "gaudit-sourceless-page.h"
#include "gaudit-task-page.h"
#include "gaudit/sourceless.h"

#define LIST_TIMEOUT_S 60

typedef struct {
    AdwStatusPage *loading;  /* weak; shown until the list is in */
    GtkStack *stack;         /* weak */
    AdwPreferencesPage *page;  /* weak */
    GPtrArray *packages[GAUDIT_SOURCELESS_GROUPS];  /* gaudit_sourceless_package * */
    gboolean have_summary;
    gaudit_sourceless_summary summary;
} ListJob;

static const struct {
    const char *title;
    const char *description;
} group_text[GAUDIT_SOURCELESS_GROUPS] = {
    [GAUDIT_SOURCELESS_ABOVE_SOURCE] = {
        N_("Newer than the software source"),
        N_("A software source offers these, but only in a lower version than the one "
           "installed. They get no updates until the source passes that version, which may "
           "never happen. This is the group that matters most."),
    },
    [GAUDIT_SOURCELESS_LEFTOVER] = {
        N_("Probably left over from an older release"),
        N_("These came from the distribution, but no software source offers them any more. "
           "They get no updates. Remove the ones you no longer need."),
    },
    [GAUDIT_SOURCELESS_OTHER_SOURCE] = {
        N_("From other places"),
        N_("Installed from a downloaded package, or from a software source that is no longer "
           "set up. Nothing keeps them up to date."),
    },
};

static gboolean on_line(const char *line, gpointer user_data)
{
    ListJob *job = user_data;
    gaudit_sourceless_package p;
    gaudit_sourceless_summary s;
    if (job->have_summary)
        return FALSE;  /* nothing after the summary */
    int r = gaudit_sourceless_parse_line(line, &p, &s);
    if (r == 1) {
        g_ptr_array_add(job->packages[p.group], g_memdup2(&p, sizeof p));
        return TRUE;
    }
    if (r == 2) {
        guint got = 0;
        for (int g = 0; g < GAUDIT_SOURCELESS_GROUPS; g++)
            got += job->packages[g]->len;
        if (s.shown != got)
            return FALSE;  /* the summary must match what came */
        job->have_summary = TRUE;
        job->summary = s;
        return TRUE;
    }
    return FALSE;
}

static void show_message(ListJob *job, const char *icon, const char *title, const char *text)
{
    if (job->loading == NULL)
        return;
    adw_status_page_set_paintable(job->loading, NULL);
    adw_status_page_set_icon_name(job->loading, icon);
    adw_status_page_set_title(job->loading, title);
    adw_status_page_set_description(job->loading, text);
}

static void fill(ListJob *job)
{
    AdwPreferencesPage *page = job->page;
    AdwPreferencesGroup *intro = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_description(intro,
        _("These installed packages are not offered by any software source in the version "
          "installed, so the system's updates do not reach them."));
    adw_preferences_page_add(page, intro);

    for (int g = 0; g < GAUDIT_SOURCELESS_GROUPS; g++) {
        GPtrArray *list = job->packages[g];
        if (list->len == 0)
            continue;
        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        g_autofree char *title = g_strdup_printf("%s (%u)", _(group_text[g].title), list->len);
        adw_preferences_group_set_title(group, title);
        adw_preferences_group_set_description(group, _(group_text[g].description));
        for (guint i = 0; i < list->len; i++) {
            const gaudit_sourceless_package *p = g_ptr_array_index(list, i);
            AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
            /* Names and versions come from the system: never markup. */
            adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
            adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), p->name);
            g_autofree char *subtitle = p->offered[0] != '\0'
                /* Translators: versions, e.g. "Installed 1.0.8-6ubuntu0.1, the source has 1.0.8-6build2". */
                ? g_strdup_printf(_("Installed %s, the source has %s"), p->version, p->offered)
                : g_strdup_printf(_("Installed %s"), p->version);
            adw_action_row_set_subtitle(row, subtitle);
            /* Versions and package names read left to right everywhere. */
            gtk_widget_set_direction(GTK_WIDGET(row), GTK_TEXT_DIR_LTR);
            adw_preferences_group_add(group, GTK_WIDGET(row));
        }
        adw_preferences_page_add(page, group);
    }
    if (job->summary.shown < job->summary.count) {
        AdwPreferencesGroup *more = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        g_autofree char *text = g_strdup_printf(_("Showing %u of %u packages."),
                                                job->summary.shown, job->summary.count);
        adw_preferences_group_set_description(more, text);
        adw_preferences_page_add(page, more);
    }
}

static void on_done(gboolean broken, gpointer user_data)
{
    ListJob *job = user_data;
    if (broken || !job->have_summary || job->summary.status == GAUDIT_SOURCELESS_UNKNOWN)
        show_message(job, "dialog-warning-symbolic", _("Could not list the packages"),
                     _("Nothing is known about them from this attempt."));
    else if (job->summary.status == GAUDIT_SOURCELESS_UNSUPPORTED)
        show_message(job, "dialog-information-symbolic", _("Not supported on this system yet"),
                     _("gAudit cannot list these packages here yet."));
    else if (job->summary.count == 0)
        show_message(job, "emblem-ok-symbolic", _("Every package has a source"), NULL);
    else if (job->stack != NULL && job->page != NULL) {
        fill(job);
        gtk_stack_set_visible_child_name(job->stack, "list");
    }

    for (int g = 0; g < GAUDIT_SOURCELESS_GROUPS; g++)
        g_ptr_array_unref(job->packages[g]);
    if (job->loading != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->loading), (gpointer *)&job->loading);
    if (job->stack != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->stack), (gpointer *)&job->stack);
    if (job->page != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->page), (gpointer *)&job->page);
    g_free(job);
}

AdwNavigationPage *gaudit_sourceless_page_new(void)
{
    AdwStatusPage *loading = ADW_STATUS_PAGE(adw_status_page_new());
#if ADW_CHECK_VERSION(1, 6, 0)
    g_autoptr(AdwSpinnerPaintable) spinner = adw_spinner_paintable_new(GTK_WIDGET(loading));
    adw_status_page_set_paintable(loading, GDK_PAINTABLE(spinner));
#else
    adw_status_page_set_icon_name(loading, "content-loading-symbolic");
#endif
    adw_status_page_set_title(loading, _("Looking at the packages…"));

    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());
    GtkStack *stack = GTK_STACK(gtk_stack_new());
    gtk_stack_add_named(stack, GTK_WIDGET(loading), "loading");
    gtk_stack_add_named(stack, GTK_WIDGET(page), "list");
    gtk_stack_set_visible_child_name(stack, "loading");

    ListJob *job = g_new0(ListJob, 1);
    for (int g = 0; g < GAUDIT_SOURCELESS_GROUPS; g++)
        job->packages[g] = g_ptr_array_new_with_free_func(g_free);
    job->loading = loading;
    job->stack = stack;
    job->page = page;
    g_object_add_weak_pointer(G_OBJECT(loading), (gpointer *)&job->loading);
    g_object_add_weak_pointer(G_OBJECT(stack), (gpointer *)&job->stack);
    g_object_add_weak_pointer(G_OBJECT(page), (gpointer *)&job->page);

    static const char *const args[] = { "packages", NULL };
    gaudit_orchestrator_start(args, LIST_TIMEOUT_S, FALSE, on_line, on_done, job);
    return gaudit_page_wrap(GTK_WIDGET(stack), _("Packages Without a Source"), "sourceless");
}
