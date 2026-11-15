/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib-unix.h>
#include <glib/gi18n.h>
#include <signal.h>
#include <string.h>

#include "gaudit-app.h"
#include "gaudit-orchestrator.h"
#include "gaudit-report-run.h"
#include "gaudit-run-page.h"
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
    gaudit_window_finish_status(job->view, gaudit_model_summary(job->app->model));
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
    const char *const *args = NULL;
#if GAUDIT_DEVELOPER_BUILD
    g_autofree char *pretend = NULL;
    const char *dev_args[2] = { NULL, NULL };
    if (gaudit_capability_pretended()[0] != '\0') {
        pretend = g_strconcat("--pretend-missing=", gaudit_capability_pretended(), NULL);
        dev_args[0] = pretend;
        args = dev_args;
    }
#endif
    gaudit_orchestrator_start(args, ORCHESTRATOR_TIMEOUT_S, FALSE, on_status_line, on_status_done, job);
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
    ".navigation-sidebar row:selected .sidebar-icon {\n"
    "  background-color: var(--accent-bg-color);\n"
    "  color: var(--accent-fg-color);\n"
    "}\n"
    /* The switch while a check waits for administrator rights: a round
     * disc in the accent colour, which shows where it is. */
    "button.gaudit-attention {\n"
    "  border-radius: 9999px;\n"
    "  background-color: var(--accent-bg-color);\n"
    "  color: var(--accent-fg-color);\n"
    "}\n";

/* --- Home's tasks at the chosen level ---------------------------------------
 *
 * Run one after another, those that need no password first, so a check
 * waiting for administrator rights never holds up the others; within the
 * lease, one password covers all that need it. A cancelled or refused
 * password stops the rest: asking again at once would only annoy. Results
 * themselves, from here or from a task's own page 2, arrive through
 * on_session_result. */

typedef struct {
    GauditApp *app;
    GauditWindow *view;
    guint level;
    GArray *order;   /* gsize: the task indexes, those without the password first */
    guint pos;       /* the next one in order */
    gsize current;
    gboolean again;  /* asked for anew (another level, Reload): start over when done */
} LevelJob;

static LevelJob *level_job;  /* the one under way, if any */

static void level_next(LevelJob *job);
static void start_level_job(GauditApp *app, GauditWindow *view);

/* status: why the tasks still waiting did not run (GAUDIT_RUN_OK when
 * every one did); they lose their spinner with that said. */
static void level_finish(LevelJob *job, gaudit_run_status status)
{
    for (guint p = job->pos; p < job->order->len; p++)
        gaudit_window_task_failed(job->view, g_array_index(job->order, gsize, p), status);
    gaudit_window_set_worst(job->view, gaudit_model_summary(job->app->model));
    GauditApp *app = job->app;
    GauditWindow *view = job->view;
    gboolean again = job->again;
    g_array_unref(job->order);
    g_free(job);
    level_job = NULL;
    if (again)
        start_level_job(app, view);
    g_object_unref(view);
    g_object_unref(app);
}

static void on_level_done(gaudit_run_status status, const GauditRunResult *result,
                          gpointer user_data)
{
    LevelJob *job = user_data;
    /* A result is already in place (on_session_result); only say why
     * nothing came. */
    if (status != GAUDIT_RUN_OK || result == NULL)
        gaudit_window_task_failed(job->view, job->current,
                                  status == GAUDIT_RUN_OK ? GAUDIT_RUN_FAILED : status);
    if (status == GAUDIT_RUN_CANCELLED || status == GAUDIT_RUN_DENIED) {
        level_finish(job, status);
        return;
    }
    level_next(job);
}

static void level_next(LevelJob *job)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (job->pos >= job->order->len) {
        level_finish(job, GAUDIT_RUN_OK);
        return;
    }
    job->current = g_array_index(job->order, gsize, job->pos++);
    gaudit_window_task_running(job->view, job->current);
    if (!gaudit_session_run(gaudit_task_home_command(&tasks[job->current], job->level), NULL,
                            on_level_done, job)) {
        /* The same plugin is already at work (e.g. from its page 2). */
        gaudit_window_task_failed(job->view, job->current, GAUDIT_RUN_OK);
        level_next(job);
    }
}

/* The checks of the level chosen on Home, when the app opens, on Reload
 * and when a level is picked. Those that need administrator rights wait
 * for the switch (the password is never asked for otherwise). */
static void start_level_job(GauditApp *app, GauditWindow *view)
{
    if (level_job != NULL) {
        /* Asked for anew while one is under way: that one finishes first,
         * then this starts; one that waits for the password would never
         * finish, so it stops now. */
        gsize n_tasks;
        const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
        level_job->again = TRUE;
        const char *command = gaudit_task_home_command(&tasks[level_job->current], level_job->level);
        if (gaudit_session_waiting_for(command))
            gaudit_session_cancel_for(command);
        return;
    }
    guint level = gaudit_window_home_level(view);
    LevelJob *job = g_new0(LevelJob, 1);
    job->app = g_object_ref(app);
    job->view = g_object_ref(view);
    job->level = level;
    job->order = g_array_new(FALSE, FALSE, sizeof(gsize));
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (int admin = 0; admin <= 1; admin++)
        for (gsize i = 0; i < n_tasks; i++)
            if (gaudit_task_home_command(&tasks[i], level) != NULL
                && gaudit_task_home_needs_admin(&tasks[i], level) == (gboolean)admin)
                g_array_append_val(job->order, i);
    level_job = job;
    /* Every task waiting its turn has its spinner from the start, and loses
     * it only when its own run is done. */
    for (guint p = 0; p < job->order->len; p++)
        gaudit_window_task_running(view, g_array_index(job->order, gsize, p));
    level_next(job);
}

/* Reload on Home: Home's checks again, as when the app opens, and the
 * reports at the chosen level; it is an explicit act, so those that need
 * the password ask for it. */
static void refresh_status(GauditApp *self, GauditWindow *view);

static void on_reload_home(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    GtkWindow *win = gtk_application_get_active_window(GTK_APPLICATION(app));
    if (!GAUDIT_IS_WINDOW(win))
        return;
    refresh_status(GAUDIT_APP(app), GAUDIT_WINDOW(win));
    start_level_job(GAUDIT_APP(app), GAUDIT_WINDOW(win));
}

static void on_run_level(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    GtkWindow *win = gtk_application_get_active_window(GTK_APPLICATION(app));
    if (GAUDIT_IS_WINDOW(win))
        start_level_job(GAUDIT_APP(app), GAUDIT_WINDOW(win));
}

/* The switch in the header bar, the only thing that asks for the password.
 * Checks waiting for administrator rights go on (the first asks); with
 * none waiting, it only gets the rights, which then cover what comes next
 * within the lease. The switch itself follows the helper
 * (on_elevated_changed), so a cancelled or refused password leaves it as
 * it was, and ends the checks that waited. */
static void on_elevate_done(gaudit_run_status status, const GauditRunResult *result,
                            gpointer app)
{
    (void)status;
    (void)result;
    (void)app;
}

static void on_elevate(GSimpleAction *action, GVariant *param, gpointer app)
{
    (void)action;
    (void)param;
    if (gaudit_session_resume() || gaudit_session_elevated())
        return;
    gaudit_session_run("elevate", NULL, on_elevate_done, app);  /* FALSE: already asked for */
}

/* A check waits for administrator rights: once per run, a toast saying
 * which and where the switch is; the switch has its disc while any waits;
 * on Home, the waiting row says so. */
static void on_waiting(const char *command, gboolean waiting, gboolean first, gpointer app)
{
    gsize index;
    const GauditTaskInfo *task = gaudit_task_for_command(command, &index);
    gboolean any = gaudit_session_any_waiting();
    for (GList *w = gtk_application_get_windows(GTK_APPLICATION(app)); w != NULL; w = w->next) {
        if (!GAUDIT_IS_WINDOW(w->data))
            continue;
        GauditWindow *view = GAUDIT_WINDOW(w->data);
        gaudit_window_set_attention(view, any);
        if (task != NULL)
            gaudit_window_task_waiting(view, index, waiting);
        if (waiting && first) {
            /* Translators: %s is a plugin, e.g. "Updates". */
            g_autofree char *text = task != NULL
                ? g_strdup_printf(_("%s needs administrator rights. Use the switch beside the title."),
                                  _(task->title))
                : g_strdup(_("This change needs administrator rights. Use the switch beside the title."));
            gaudit_window_toast(view, text);
        }
    }
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
    { .name = "run-level",    .activate = on_run_level },
    { .name = "reload-home",  .activate = on_reload_home },
    { .name = "elevate",      .activate = on_elevate },
};

static void set_accel(GApplication *app, const char *action, const char *accel)
{
    const char *accels[] = { accel, NULL };
    gtk_application_set_accels_for_action(GTK_APPLICATION(app), action, accels);
}

/* Every result of a run, whoever started it (Home's button or a task's
 * page 2): into the model under the task's id, replacing an earlier one,
 * and onto Home's row for that task in every window, so the two never
 * disagree. */
/* A task's latest result onto its Home row in every window, and into the
 * model under the task's id, so the summary counts it. */
static void record(GauditApp *self, gsize i, gaudit_verdict verdict, const char *title,
                   GPtrArray *rows)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (gaudit_model_add_finding(self->model, tasks[i].id, verdict) != GAUDIT_OK)
        g_warning("gaudit: could not record finding %s", tasks[i].id);
    gaudit_verdict worst = gaudit_model_summary(self->model);
    for (GList *w = gtk_application_get_windows(GTK_APPLICATION(self)); w != NULL; w = w->next)
        if (GAUDIT_IS_WINDOW(w->data)) {
            gaudit_window_task_report(GAUDIT_WINDOW(w->data), i, verdict, title, rows);
            gaudit_window_set_worst(GAUDIT_WINDOW(w->data), worst);
        }
}

typedef struct {
    GauditApp *app;
    gsize task;
} CachedReport;

/* The report on a new collection: its verdict and title for Home. */
static void on_cached_report(GauditReport *report, gpointer user_data)
{
    CachedReport *c = user_data;
    gsize n_tasks;
    const GauditTaskInfo *task = &gaudit_tasks_get(&n_tasks)[c->task];
    g_autofree char *title = report != NULL ? gaudit_report_title(report, task->text_domain)
                                            : g_strdup(_("The report could not be made"));
    g_autoptr(GPtrArray) rows = report != NULL ? gaudit_report_home_rows(report, task->text_domain)
                                               : NULL;
    record(c->app, c->task, gaudit_report_verdict(report), title, rows);
    gaudit_report_free(report);
    g_object_unref(c->app);
    g_free(c);
}

/* A cached collection changed in place (a finding checked again after a
 * fix): Home's row follows, from the same cache. */
static void on_cache_changed(const GauditTaskInfo *task, gpointer app)
{
    gsize index;
    const char *command = gaudit_cache_command(task);
    GPtrArray *lines = gaudit_cache_lines(task, NULL);
    if (command == NULL || lines == NULL || gaudit_task_for_command(command, &index) != task)
        return;
    CachedReport *c = g_new0(CachedReport, 1);
    c->app = g_object_ref(GAUDIT_APP(app));
    c->task = index;
    gaudit_report_run(task, command, lines, on_cached_report, c);
}

static void on_session_result(const char *command, const GauditRunResult *result,
                              gpointer app)
{
    GauditApp *self = GAUDIT_APP(app);
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    /* Every task has its row in its group on Home: its result is kept for
     * the session, shown there, and counts in the summary. */
    gsize found;
    if (gaudit_task_for_command(command, &found) == NULL)
        return;
    for (gsize i = found; i == found; i++) {
        if (result->kind == GAUDIT_RESULT_COLLECTION) {
            /* Kept for the session; the plugin's report on it decides. Every
             * watcher hears of it: Home makes its rows (on_cache_changed),
             * and a report page open behind a fix page makes itself again,
             * so checking again after a fix shows where it is seen. */
            gaudit_cache_store(&tasks[i], command, result->lines, result->full,
                               (const char *const *)result->args);
            gaudit_cache_changed(&tasks[i]);
            continue;
        }
        g_autofree char *title = gaudit_run_result_title(result);
        record(self, i, gaudit_run_result_verdict(result), title, NULL);
    }
}

/* The user/administrator switch follows the helper in every window. */
static void on_elevated_changed(gboolean on, gpointer app)
{
    for (GList *w = gtk_application_get_windows(GTK_APPLICATION(app)); w != NULL; w = w->next)
        if (GAUDIT_IS_WINDOW(w->data))
            gaudit_window_set_elevated(GAUDIT_WINDOW(w->data), on);
}

/* With the last window gone, so are the elevated rights: nobody would see
 * the switch. (Jobs that go on in the background come later.) */
static void on_window_removed(GtkApplication *app, GtkWindow *window, gpointer user_data)
{
    (void)window;
    (void)user_data;
    /* The last window gone: the app ends. Runs under way stop (the close
     * dialog asked first if one was heavy), and with them the holds they
     * keep on the app. */
    if (gtk_application_get_windows(app) == NULL) {
        gaudit_session_cancel();
        gaudit_session_end();
    }
}

/* Ctrl-C in the terminal, or a plain kill: end at once, no questions. The
 * orchestrators die with the app (PR_SET_PDEATHSIG). */
static gboolean on_quit_signal(gpointer app)
{
    g_application_quit(G_APPLICATION(app));
    return G_SOURCE_CONTINUE;
}

static void gaudit_app_startup(GApplication *app)
{
    G_APPLICATION_CLASS(gaudit_app_parent_class)->startup(app);
    g_unix_signal_add(SIGINT, on_quit_signal, app);
    gaudit_cache_watch(on_cache_changed, app);
    g_unix_signal_add(SIGTERM, on_quit_signal, app);

    /* A selectable label (the command fields) must not select all of its
     * text when it gets focus: the user expects to select it, finds it
     * already selected, and has to undo that first. */
    g_object_set(gtk_settings_get_default(), "gtk-label-select-on-focus", FALSE, NULL);

    gaudit_session_set_elevated_listener(on_elevated_changed, app);
    gaudit_session_watch_waiting(on_waiting, app);
    gaudit_session_set_result_listener(on_session_result, app);
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
        start_level_job(self, view);  /* the password only ever from the switch */
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

#if GAUDIT_DEVELOPER_BUILD
static int on_local_options(GApplication *app, GVariantDict *options, gpointer data)
{
    (void)app; (void)data;
    const char *ids = NULL;
    if (g_variant_dict_lookup(options, "pretend-missing", "&s", &ids)
        && gaudit_capability_pretend_missing(ids) != 0) {
        g_printerr("gaudit: --pretend-missing takes ids like ufw,clamav\n");
        return 2;
    }
    return -1;  /* go on */
}
#endif

static void gaudit_app_init(GauditApp *self)
{
#if GAUDIT_DEVELOPER_BUILD
    /* Developer builds only: see the pages for missing software. */
    g_application_add_main_option(G_APPLICATION(self), "pretend-missing", 0, G_OPTION_FLAG_NONE,
                                  G_OPTION_ARG_STRING,
                                  "Pretend these tools are not installed (developer builds)",
                                  "ufw,clamav");
    g_signal_connect(self, "handle-local-options", G_CALLBACK(on_local_options), NULL);
#endif
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
