/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-app.h"
#include "gaudit-orchestrator.h"
#include "gaudit-session.h"
#include "gaudit-task.h"
#include "gaudit-window.h"
#include "gaudit/backend.h"
#include "gaudit/model.h"
#include "gaudit/probe.h"

struct _GauditApp {
    AdwApplication parent_instance;
    gaudit_model *model;
};

G_DEFINE_FINAL_TYPE(GauditApp, gaudit_app, ADW_TYPE_APPLICATION)

/* --- Status refresh through the orchestrator ------------------------------
 *
 * The probes run in gaudit-orchestrator, a separate process started for
 * each refresh, so the GUI never blocks and never runs check code itself.
 * It writes one line per result as soon as that result is known, and each
 * Home row is filled in as its line arrives.
 *
 * Every line is parsed strictly. A line that breaks the protocol (bad
 * format, a kind repeated, too much output) means none of it can be
 * trusted: every row becomes unknown, also those already shown. A row
 * whose answer never came (timeout, a task that failed) becomes unknown on
 * its own. Never a guess. */

#define ORCHESTRATOR_TIMEOUT_S 60

typedef struct {
    GauditApp *app;
    GauditWindow *view;
    gaudit_probe_result results[GAUDIT_PROBE_COUNT];
    gboolean seen[GAUDIT_PROBE_COUNT];
} RefreshJob;

static gboolean on_status_line(const char *line, gpointer user_data)
{
    RefreshJob *job = user_data;
    gaudit_probe_result r;
    if (gaudit_probe_parse_line(line, &r) != 0 || job->seen[r.kind])
        return FALSE;  /* malformed, or a kind repeated */
    job->seen[r.kind] = TRUE;
    job->results[r.kind] = r;
    gaudit_window_show_probe(job->view, &r);
    return TRUE;
}

static void on_status_done(gboolean broken, gpointer user_data)
{
    RefreshJob *job = user_data;
    gaudit_probe_result defaults[GAUDIT_PROBE_COUNT];
    gaudit_probe_init(defaults);
    if (broken)
        g_warning("gaudit: the status check broke the protocol; showing every row as unknown");
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        if (broken || !job->seen[k]) {
            job->results[k] = defaults[k];
            gaudit_window_show_probe(job->view, &job->results[k]);
        }
        const gaudit_probe_result *r = &job->results[k];
        if (r->applicable && gaudit_model_add_finding(job->app->model, r->id, r->verdict) != GAUDIT_OK)
            g_warning("gaudit: could not record finding %s", r->id);
    }
    gaudit_window_finish_status(job->view, gaudit_model_worst(job->app->model));
    g_object_unref(job->view);
    g_object_unref(job->app);
    g_free(job);
}

static void refresh_status(GauditApp *self, GauditWindow *view)
{
    RefreshJob *job = g_new0(RefreshJob, 1);
    job->app = g_object_ref(self);
    job->view = g_object_ref(view);
    gaudit_window_begin_status(view);
    gaudit_orchestrator_start(NULL, ORCHESTRATOR_TIMEOUT_S, FALSE, on_status_line, on_status_done, job);
}

/* Sidebar icons sit on a filled circle. It is grey, like the row
 * highlight, for pages that exist but are not shown, and accent-coloured
 * for the page that is open. Row backgrounds (hover, selected) come from
 * the "navigation-sidebar" style. */
static const char app_css[] =
    ".navigation-sidebar row .sidebar-icon {\n"
    "  -gtk-icon-size: 16px;\n"
    "  min-width: 16px;\n"
    "  min-height: 16px;\n"
    "  padding: 8px;\n"
    "  border-radius: 9999px;\n"
    "  background-color: alpha(var(--window-fg-color), 0.1);\n"
    "  color: var(--window-fg-color);\n"
    "}\n"
    ".elevated-marker {\n"
    "  color: var(--destructive-color);\n"
    "}\n"
    ".navigation-sidebar row:selected .sidebar-icon {\n"
    "  background-color: var(--accent-bg-color);\n"
    "  color: var(--accent-fg-color);\n"
    "}\n";

/* --- Home's checks that need the password ---------------------------------
 *
 * Run one after another through the session, so one password covers all
 * of them (the helper's lease). A cancelled or refused password stops the
 * rest: asking again at once would only annoy. Each result goes into the
 * model under the task's id, replacing an earlier one. */

typedef struct {
    GauditApp *app;
    GauditWindow *view;
    gsize next;      /* the task index to look at next */
    gsize current;
} ElevatedJob;

static void elevated_next(ElevatedJob *job);

static void elevated_finish(ElevatedJob *job)
{
    gaudit_window_elevated_end(job->view, gaudit_model_worst(job->app->model));
    g_object_unref(job->view);
    g_object_unref(job->app);
    g_free(job);
}

static void on_elevated_done(gaudit_run_status status, const gaudit_firewall_report *result,
                             gpointer user_data)
{
    ElevatedJob *job = user_data;
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (status == GAUDIT_RUN_OK && result != NULL
        && gaudit_model_add_finding(job->app->model, tasks[job->current].id, result->verdict) != GAUDIT_OK)
        g_warning("gaudit: could not record finding %s", tasks[job->current].id);
    gaudit_window_elevated_result(job->view, job->current, status, result);
    if (status == GAUDIT_RUN_CANCELLED || status == GAUDIT_RUN_DENIED) {
        elevated_finish(job);
        return;
    }
    elevated_next(job);
}

static void elevated_next(ElevatedJob *job)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    while (job->next < n_tasks && !tasks[job->next].home_elevated)
        job->next++;
    if (job->next >= n_tasks) {
        elevated_finish(job);
        return;
    }
    job->current = job->next++;
    if (!gaudit_session_run(tasks[job->current].run_command, NULL, on_elevated_done, job)) {
        gaudit_window_elevated_busy(job->view);
        elevated_finish(job);
    }
}

static void on_run_elevated(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    GtkWindow *win = gtk_application_get_active_window(GTK_APPLICATION(app));
    if (!GAUDIT_IS_WINDOW(win))
        return;
    ElevatedJob *job = g_new0(ElevatedJob, 1);
    job->app = g_object_ref(GAUDIT_APP(app));
    job->view = g_object_ref(GAUDIT_WINDOW(win));
    gaudit_window_elevated_begin(job->view);
    elevated_next(job);
}

/* --- Actions (primary menu and shortcuts) --------------------------------- */

static GtkWidget *active_window(gpointer app)
{
    return GTK_WIDGET(gtk_application_get_active_window(GTK_APPLICATION(app)));
}

static void on_preferences(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    AdwPreferencesDialog *dialog = ADW_PREFERENCES_DIALOG(adw_preferences_dialog_new());
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());
    adw_preferences_page_set_title(page, _("General"));
    adw_preferences_page_set_icon_name(page, "preferences-system-symbolic");
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_description(group, _("There is nothing to set yet."));
    adw_preferences_page_add(page, group);
    adw_preferences_dialog_add(dialog, page);
    adw_dialog_present(ADW_DIALOG(dialog), active_window(app));
}

static const struct {
    const char *title;  /* N_() */
    const char *accel;
} shortcuts[] = {
    { N_("Open Main Menu"),     "F10" },
    { N_("Preferences"),        "<Control>comma" },
    { N_("Keyboard Shortcuts"), "<Control>question" },
    { N_("Quit"),               "<Control>q" },
};

static void on_shortcuts(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
#if ADW_CHECK_VERSION(1, 8, 0)
    AdwShortcutsDialog *dialog = ADW_SHORTCUTS_DIALOG(adw_shortcuts_dialog_new());
    AdwShortcutsSection *section = adw_shortcuts_section_new(NULL);
    for (gsize i = 0; i < G_N_ELEMENTS(shortcuts); i++)
        adw_shortcuts_section_add(section,
            adw_shortcuts_item_new(_(shortcuts[i].title), shortcuts[i].accel));
    adw_shortcuts_dialog_add(dialog, section);
    adw_dialog_present(ADW_DIALOG(dialog), active_window(app));
#else
    /* libadwaita < 1.8 (e.g. Debian 13) has no AdwShortcutsDialog; show the
     * same list as rows, avoiding the deprecated GtkShortcutsWindow. */
    AdwPreferencesDialog *dialog = ADW_PREFERENCES_DIALOG(adw_preferences_dialog_new());
    adw_dialog_set_title(ADW_DIALOG(dialog), _("Keyboard Shortcuts"));
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    for (gsize i = 0; i < G_N_ELEMENTS(shortcuts); i++) {
        AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), _(shortcuts[i].title));
        GtkWidget *label = gtk_shortcut_label_new(shortcuts[i].accel);
        gtk_widget_set_valign(label, GTK_ALIGN_CENTER);
        adw_action_row_add_suffix(row, label);
        adw_preferences_group_add(group, GTK_WIDGET(row));
    }
    adw_preferences_page_add(page, group);
    adw_preferences_dialog_add(dialog, page);
    adw_dialog_present(ADW_DIALOG(dialog), active_window(app));
#endif
}

static void on_about(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    AdwAboutDialog *about = ADW_ABOUT_DIALOG(adw_about_dialog_new());
    adw_about_dialog_set_application_name(about, GAUDIT_APP_NAME);
    adw_about_dialog_set_application_icon(about, GAUDIT_APP_ID);
    adw_about_dialog_set_version(about, GAUDIT_VERSION);
    adw_about_dialog_set_comments(about, _("Check the security status of this computer"));
    adw_about_dialog_set_developer_name(about, GAUDIT_DEVELOPER);
    adw_about_dialog_set_copyright(about, "© 2026 " GAUDIT_DEVELOPER);
    adw_about_dialog_set_license_type(about, GTK_LICENSE_GPL_3_0_ONLY);
    adw_about_dialog_set_website(about, GAUDIT_WEBSITE);
    adw_about_dialog_set_issue_url(about, GAUDIT_WEBSITE "/issues");
    /* Translators: Replace with your names, one per line. */
    const char *credits = _("translator-credits");
    if (g_strcmp0(credits, "translator-credits") != 0)
        adw_about_dialog_set_translator_credits(about, credits);
    adw_dialog_present(ADW_DIALOG(about), active_window(app));
}

static void on_quit(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    /* TODO: ask about running jobs first (see AGENTS.md, User interface). */
    g_application_quit(G_APPLICATION(app));
}

static const GActionEntry app_actions[] = {
    { .name = "preferences", .activate = on_preferences },
    { .name = "shortcuts",   .activate = on_shortcuts },
    { .name = "about",       .activate = on_about },
    { .name = "quit",        .activate = on_quit },
    { .name = "run-elevated", .activate = on_run_elevated },
};

static void set_accel(GApplication *app, const char *action, const char *accel)
{
    const char *accels[] = { accel, NULL };
    gtk_application_set_accels_for_action(GTK_APPLICATION(app), action, accels);
}

/* The red disc follows the helper in every window. */
static void on_elevated_changed(gboolean on, gpointer app)
{
    for (GList *w = gtk_application_get_windows(GTK_APPLICATION(app)); w != NULL; w = w->next)
        if (GAUDIT_IS_WINDOW(w->data))
            gaudit_window_set_elevated(GAUDIT_WINDOW(w->data), on);
}

/* With the last window gone, so are the elevated rights: nobody would see
 * the red disc. (Jobs that go on in the background come later.) */
static void on_window_removed(GtkApplication *app, GtkWindow *window, gpointer user_data)
{
    (void)window;
    (void)user_data;
    if (gtk_application_get_windows(app) == NULL)
        gaudit_session_end();
}

static void gaudit_app_startup(GApplication *app)
{
    G_APPLICATION_CLASS(gaudit_app_parent_class)->startup(app);

    gaudit_session_set_elevated_listener(on_elevated_changed, app);
    g_signal_connect(app, "window-removed", G_CALLBACK(on_window_removed), NULL);

    g_action_map_add_action_entries(G_ACTION_MAP(app), app_actions,
                                    G_N_ELEMENTS(app_actions), app);
    set_accel(app, "app.preferences", "<Control>comma");
    set_accel(app, "app.shortcuts", "<Control>question");
    set_accel(app, "app.quit", "<Control>q");

    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_string(css, app_css);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
                                               GTK_STYLE_PROVIDER(css),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}

static void gaudit_app_activate(GApplication *app)
{
    GauditApp *self = GAUDIT_APP(app);
    GtkWindow *win = gtk_application_get_active_window(GTK_APPLICATION(app));

    if (win == NULL) {
        GauditWindow *view = gaudit_window_new(GTK_APPLICATION(app));
        refresh_status(self, view);
        win = GTK_WINDOW(view);
    }
    gtk_window_present(win);
}

static void gaudit_app_finalize(GObject *object)
{
    GauditApp *self = GAUDIT_APP(object);

    gaudit_model_free(self->model);
    G_OBJECT_CLASS(gaudit_app_parent_class)->finalize(object);
}

static void gaudit_app_class_init(GauditAppClass *klass)
{
    G_OBJECT_CLASS(klass)->finalize = gaudit_app_finalize;
    G_APPLICATION_CLASS(klass)->startup = gaudit_app_startup;
    G_APPLICATION_CLASS(klass)->activate = gaudit_app_activate;
}

static void gaudit_app_init(GauditApp *self)
{
    /* Only fails on out-of-memory, which GLib treats as fatal anyway. */
    if (gaudit_model_new(&self->model) != GAUDIT_OK)
        g_error("gaudit: could not allocate model");
}

GauditApp *gaudit_app_new(void)
{
    return g_object_new(GAUDIT_TYPE_APP,
                        "application-id", GAUDIT_APP_ID,
                        "flags", G_APPLICATION_DEFAULT_FLAGS,
                        NULL);
}
