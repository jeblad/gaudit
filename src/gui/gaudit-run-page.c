/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-category.h"
#include "gaudit-firewall-text.h"
#include "gaudit-run-page.h"
#include "gaudit-report-run.h"
#include "gaudit-session.h"
#include "gaudit/backend.h"
#include "gaudit-task-page.h"
#include "gaudit/run.h"

typedef struct {
    AdwStatusPage *status;  /* weak: the page may be left while the run goes on */
    const GauditTaskInfo *task;
    char *command;          /* the run's command (the plugin's own, or Home's for a reload) */
    GStrv args;             /* the run's parameters (the plugin's folders); NULL: Home's run */
    guint tick_id;          /* shows the progress of a run as the user */
    gint64 next_ask;        /* when to ask whether to go on (monotonic, µs) */
    GtkWidget *ask;         /* weak: the "keep going?" buttons, while shown */
    guint waiting_id;       /* hears when its run waits for administrator rights */
    gaudit_firewall_report firewall;
} RunJob;

static void show(RunJob *job, const char *icon, const char *title, const char *description)
{
    if (job->status == NULL)
        return;
    adw_status_page_set_paintable(job->status, NULL);
    adw_status_page_set_icon_name(job->status, icon);
    adw_status_page_set_title(job->status, title);
    adw_status_page_set_description(job->status, description);
}

static GtkWidget *small_note(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_add_css_class(label, "dim-label");
    gtk_widget_add_css_class(label, "caption");
    return label;
}

static void on_choose_clicked(GtkButton *button, gpointer user_data)
{
    const GauditCategory *category = user_data;
    GtkWidget *nav = gtk_widget_get_ancestor(GTK_WIDGET(button), ADW_TYPE_NAVIGATION_VIEW);
    if (nav != NULL && category != NULL)
        adw_navigation_view_push(ADW_NAVIGATION_VIEW(nav),
                                 gaudit_category_page_new(category, gaudit_pkg_backend_default()));
}

/* The manual way to switch the firewall on, under the warning. */
static void show_enable(RunJob *job)
{
    if (job->status == NULL)
        return;
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    const GauditCategory *firewalls = gaudit_category_for_probe("status.firewall");
    /* Fixed commands from the category's table, for the program the
     * backend sees installed (presentation only; the user runs it). */
    const char *command = gaudit_category_enable_command(firewalls, pkg);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    if (command != NULL) {
        GtkWidget *intro = gtk_label_new(_("To switch it on, run this command in a terminal:"));
        gtk_label_set_wrap(GTK_LABEL(intro), TRUE);
        gtk_label_set_xalign(GTK_LABEL(intro), 0.0f);
        gtk_box_append(GTK_BOX(box), intro);
        gtk_box_append(GTK_BOX(box), gaudit_command_field_new(command));
        gtk_box_append(GTK_BOX(box), small_note(
            _("If you use this computer from another one, for example over SSH, allow that "
              "in the firewall first, or you will be shut out.")));
    } else {
        gtk_box_append(GTK_BOX(box), small_note(_("No known firewall program is installed.")));
        GtkWidget *choose = gtk_button_new_with_label(_("Choose a Firewall"));
        gtk_widget_add_css_class(choose, "pill");
        gtk_widget_add_css_class(choose, "suggested-action");
        gtk_widget_set_halign(choose, GTK_ALIGN_CENTER);
        g_signal_connect(choose, "clicked", G_CALLBACK(on_choose_clicked), (gpointer)firewalls);
        gtk_box_append(GTK_BOX(box), choose);
    }
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(job->status, clamp);
}

static void show_firewall(RunJob *job)
{
    const char *icon;
    g_autofree char *title = NULL, *description = NULL;
    gaudit_firewall_text(&job->firewall, &icon, &title, &description);
    show(job, icon, title, description);
    if (job->firewall.verdict == GAUDIT_VERDICT_WARNING)
        show_enable(job);
}

char *gaudit_run_result_title(const GauditRunResult *r)
{
    if (r == NULL)
        return g_strdup(_("Unknown"));
    if (r->kind == GAUDIT_RESULT_FIREWALL) {
        const char *icon;
        char *title = NULL, *description = NULL;
        gaudit_firewall_text(&r->firewall, &icon, &title, &description);
        g_free(description);
        return title;
    }
    const gaudit_integrity_report *ir = &r->integrity;
    switch (ir->verdict) {
    case GAUDIT_VERDICT_OK:
        return g_strdup(_("No changed package files found"));
    case GAUDIT_VERDICT_WARNING: {
        unsigned long n = ir->changed + ir->missing;
        return g_strdup_printf(ngettext("%lu package file has changed or is missing",
                                        "%lu package files have changed or are missing", n), n);
    }
    default:
        return g_strdup(_("Some package files could not be checked"));
    }
}

/* --- The run ---------------------------------------------------------- */

/* Its run waits for the password, which only the switch gives: say where. */
static void on_waiting(const char *command, gboolean waiting, gboolean first, gpointer user_data)
{
    (void)first;
    RunJob *job = user_data;
    if (job->status == NULL || gaudit_session_running_for(job->command) != command)
        return;
    if (!waiting) {
        /* Going on: the password dialog comes now (on_progress follows). */
        adw_status_page_set_title(job->status, _("Waiting for the password"));
        adw_status_page_set_description(job->status,
                                        job->task->run_waiting != NULL ? _(job->task->run_waiting) : NULL);
        return;
    }
    adw_status_page_set_title(job->status, _("Waiting for administrator rights"));
    adw_status_page_set_description(job->status,
        _("Use the switch beside the title to give the password. The check goes on "
          "from there."));
}

static void watch_waiting(RunJob *job)
{
    if (job->waiting_id == 0)
        job->waiting_id = gaudit_session_watch_waiting(on_waiting, job);
    if (gaudit_session_waiting_for(job->command))
        on_waiting(gaudit_session_running_for(job->command), TRUE, FALSE, job);
}

static void on_progress(gpointer user_data)
{
    RunJob *job = user_data;
    if (job->status != NULL) {
        adw_status_page_set_title(job->status, _(job->task->run_running));
        adw_status_page_set_description(job->status, NULL);
    }
}

static void job_free(RunJob *job)
{
    if (job->waiting_id != 0)
        gaudit_session_unwatch_waiting(job->waiting_id);
    if (job->tick_id != 0)
        g_source_remove(job->tick_id);
    if (job->ask != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->ask), (gpointer *)&job->ask);
    if (job->status != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->status), (gpointer *)&job->status);
    g_strfreev(job->args);
    g_free(job->command);
    g_free(job);
}

/* A fix the report names, built by the plugin from the collected line. */
typedef struct {
    const GauditTaskInfo *task;
    GPtrArray *lines;
} FixData;

static void fix_data_free(gpointer p)
{
    FixData *d = p;
    g_ptr_array_unref(d->lines);
    g_free(d);
}

static AdwNavigationPage *fix_page(const char *fix_id, guint item, gpointer user_data)
{
    FixData *d = user_data;
    if (d->task->fix_page == NULL || item >= d->lines->len)
        return NULL;
    return d->task->fix_page(fix_id, d->lines, item);
}

typedef struct {
    RunJob *job;
    GPtrArray *lines;
} ReportJob;

/* A report page follows its task's cache: a finding checked again after a
 * fix makes the report again in place, so going back from the fix page
 * shows it as it is now. */
typedef struct {
    AdwStatusPage *status;  /* weak */
    const GauditTaskInfo *task;
    guint watch;
} Follow;

static void follow_free(gpointer p, GObject *gone)
{
    (void)gone;
    Follow *f = p;
    gaudit_cache_unwatch(f->watch);
    g_free(f);
}

static void on_report(GauditReport *report, gpointer user_data);

static void on_cache_changed(const GauditTaskInfo *task, gpointer user_data)
{
    Follow *f = user_data;
    const char *command = gaudit_cache_command(task);
    GPtrArray *lines = gaudit_cache_lines(task, NULL);
    if (task != f->task || f->status == NULL || command == NULL || lines == NULL)
        return;
    RunJob *job = g_new0(RunJob, 1);
    job->status = f->status;
    job->task = task;
    g_object_add_weak_pointer(G_OBJECT(f->status), (gpointer *)&job->status);
    ReportJob *rj = g_new0(ReportJob, 1);
    rj->job = job;
    rj->lines = g_ptr_array_ref(lines);
    gaudit_report_run(task, command, rj->lines, on_report, rj);
}

static void follow(AdwStatusPage *status, const GauditTaskInfo *task)
{
    if (g_object_get_data(G_OBJECT(status), "gaudit-follows") != NULL)
        return;
    Follow *f = g_new0(Follow, 1);
    f->status = status;  /* cleared with the page: follow_free runs first */
    f->task = task;
    f->watch = gaudit_cache_watch(on_cache_changed, f);
    g_object_set_data(G_OBJECT(status), "gaudit-follows", GINT_TO_POINTER(1));
    /* The page gone: so is the watch. */
    g_object_weak_ref(G_OBJECT(status), follow_free, f);
}

static void on_report(GauditReport *report, gpointer user_data)
{
    ReportJob *rj = user_data;
    RunJob *job = rj->job;
    if (job->status != NULL && report != NULL) {
        FixData *d = g_new0(FixData, 1);
        d->task = job->task;
        d->lines = g_ptr_array_ref(rj->lines);
        gaudit_report_show(job->status, report, job->task->text_domain, fix_page, d, fix_data_free);
        follow(job->status, job->task);
    } else if (report == NULL) {
        show(job, "dialog-warning-symbolic", _("The report could not be made"),
             _("The check ran, but its report could not be put together."));
    }
    gaudit_report_free(report);
    g_ptr_array_unref(rj->lines);
    g_free(rj);
    job_free(job);
}

static void on_run_done(gaudit_run_status status, const GauditRunResult *result,
                        gpointer user_data)
{
    RunJob *job = user_data;
    if (job->tick_id != 0) {
        g_source_remove(job->tick_id);
        job->tick_id = 0;
    }
    if (job->status != NULL && job->ask != NULL)
        adw_status_page_set_child(job->status, NULL);
    if (status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_COLLECTION) {
        /* The plugin's rule script makes the report from what was collected. */
        if (job->status != NULL) {
            adw_status_page_set_title(job->status, _("Writing the report…"));
            adw_status_page_set_description(job->status, NULL);
        }
        ReportJob *rj = g_new0(ReportJob, 1);
        rj->job = job;
        rj->lines = g_ptr_array_ref(result->lines);
        gaudit_report_run(job->task, job->command, rj->lines, on_report, rj);
        return;
    } else if (status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_FIREWALL) {
        job->firewall = result->firewall;
        show_firewall(job);
    } else if (status == GAUDIT_RUN_CANCELLED && !gaudit_command_needs_admin(job->command)) {
        show(job, "dialog-information-symbolic", _("The search was stopped"),
             _("Nothing is known from this run. Run it again, perhaps with fewer folders."));
    } else if (status == GAUDIT_RUN_CANCELLED) {
        show(job, "dialog-information-symbolic", _("The check was cancelled"),
             _("No password was given, so nothing was checked."));
    } else if (status == GAUDIT_RUN_DENIED) {
        show(job, "dialog-password-symbolic", _("Not authorized"),
             _("The password was not accepted, or this account may not run administrator checks."));
    } else {
        show(job, "dialog-warning-symbolic", _("The check could not be completed"),
             _("Nothing is known from this run."));
    }
    job_free(job);
}

/* --- A long run as the user ---------------------------------------------
 *
 * It reports how far it has come, so the user sees it is alive, and after
 * a while page 2 asks whether to go on: the search goes on meanwhile, and
 * Keep Going asks again later. No hard limit for the full run. */

#define ASK_AFTER_US (10 * 60 * G_USEC_PER_SEC)

static void on_keep_going(GtkButton *button, gpointer user_data)
{
    (void)button;
    RunJob *job = user_data;
    job->next_ask = g_get_monotonic_time() + ASK_AFTER_US;
    if (job->status != NULL) {
        adw_status_page_set_child(job->status, NULL);
        adw_status_page_set_title(job->status, _(job->task->run_running));  /* searching again */
    }
}

static void on_stop(GtkButton *button, gpointer user_data)
{
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    gaudit_session_cancel_for(((RunJob *)user_data)->command);  /* on_run_done says it was stopped */
}

static gboolean on_tick(gpointer user_data)
{
    RunJob *job = user_data;
    if (job->status == NULL || gaudit_session_running_for(job->command) == NULL) {
        job->tick_id = 0;
        return G_SOURCE_REMOVE;
    }
    const char *where = NULL;
    guint64 n = gaudit_session_progress(job->command, &where);
    if (n > 0) {
        /* Translators: %s is a number, e.g. "1 234 567". */
        g_autofree char *count = g_strdup_printf("%'" G_GUINT64_FORMAT, n);
        g_autofree char *shown = where != NULL ? g_utf8_make_valid(where, -1) : NULL;
        /* The status page's description is markup: the folder comes from the
         * system, so it is escaped. */
        g_autofree char *safe = shown != NULL ? g_markup_escape_text(shown, -1) : NULL;
        g_autofree char *text = safe != NULL
            /* Translators: "<count> … · now in <folder>", e.g. "/mnt/backup". */
            ? g_strdup_printf(_("Looked at %s files and folders so far · now in %s"), count, safe)
            : g_strdup_printf(_("Looked at %s files and folders so far."), count);
        adw_status_page_set_description(job->status, text);
    }
    if (job->ask == NULL && g_get_monotonic_time() >= job->next_ask) {
        adw_status_page_set_title(job->status, _("The search is taking a long time. Keep going?"));
        /* Side by side, as a dialog's buttons. */
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
        gtk_box_set_homogeneous(GTK_BOX(box), TRUE);
        GtkWidget *go = gaudit_action_button_new(_("Keep Going"), FALSE, TRUE);
        gtk_widget_set_halign(go, GTK_ALIGN_FILL);
        g_signal_connect(go, "clicked", G_CALLBACK(on_keep_going), job);
        GtkWidget *stop = gaudit_action_button_new(_("Stop"), FALSE, FALSE);
        gtk_widget_add_css_class(stop, "destructive-action");
        gtk_widget_set_halign(stop, GTK_ALIGN_FILL);
        g_signal_connect(stop, "clicked", G_CALLBACK(on_stop), job);
        gtk_box_append(GTK_BOX(box), stop);
        gtk_box_append(GTK_BOX(box), go);
        adw_status_page_set_child(job->status, box);
        job->ask = box;
        g_object_add_weak_pointer(G_OBJECT(box), (gpointer *)&job->ask);
    }
    return G_SOURCE_CONTINUE;
}

/* While a run as the user goes on: its progress, every second. */
static void watch_progress(RunJob *job)
{
    if (gaudit_command_needs_admin(job->command) || job->tick_id != 0)
        return;
    job->next_ask = g_get_monotonic_time() + ASK_AFTER_US;
    job->tick_id = g_timeout_add_seconds(1, on_tick, job);
}

/* --- A run already under way --------------------------------------------
 *
 * Run while an earlier run is still going (e.g. Home's collection): the
 * same command (the same parameters) waits for that run and shows its
 * result, "In progress, processing…"; a different one asks "In progress,
 * restart?", so a long run, or one out of control, can be stopped. Either
 * way this page's own run starts once the other has ended. A general
 * method for every plugin. */

static void start_or_ask(RunJob *job);

/* The earlier run has ended (finished, or stopped): now ours. */
static void on_other_done(gaudit_run_status status, const GauditRunResult *result,
                          gpointer user_data)
{
    (void)status;
    (void)result;
    RunJob *job = user_data;
    if (job->status == NULL) {
        job_free(job);  /* the page is gone: nobody asked for it any more */
        return;
    }
    adw_status_page_set_child(job->status, NULL);
    start_or_ask(job);
}

static void on_restart_clicked(GtkButton *button, gpointer user_data)
{
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    gaudit_session_cancel_for(((RunJob *)user_data)->command);  /* on_other_done starts ours */
}

static void on_wait_clicked(GtkButton *button, gpointer user_data)
{
    RunJob *job = user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    if (job->status != NULL)
        adw_status_page_set_title(job->status, _("Waiting for the other check to finish…"));
}

static void start_or_ask(RunJob *job)
{
    const char *running = gaudit_session_running_for(job->command);
    if (running == NULL) {
        if (job->status != NULL)
            adw_status_page_set_title(job->status, _(job->task->run_running));
        watch_waiting(job);  /* before it starts: it may wait at once */
        if (!gaudit_session_run_args(job->command, (const char *const *)job->args,
                                     on_progress, on_run_done, job)) {
            show(job, "dialog-warning-symbolic", _("The check could not be started"), NULL);
            job_free(job);
            return;
        }
        watch_progress(job);
        return;
    }
    if (gaudit_session_running_is(job->command, (const char *const *)job->args)) {
        /* The same parameters: that run is this one. */
        if (job->status != NULL) {
            adw_status_page_set_title(job->status, _("In progress, processing…"));
            adw_status_page_set_description(job->status,
                _("This check was already running. Its result is shown here when it is done."));
        }
        gaudit_session_attach(job->command, NULL, on_run_done, job);
        watch_waiting(job);
        watch_progress(job);
        return;
    }
    if (job->status != NULL) {
        adw_status_page_set_title(job->status, _("In progress, restart?"));
        adw_status_page_set_description(job->status,
            _("Another check is still running. Stop it and start this one, or wait until it "
              "has finished; this one starts then."));
        /* Side by side, as a dialog's buttons. */
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
        gtk_box_set_homogeneous(GTK_BOX(box), TRUE);
        GtkWidget *restart = gaudit_action_button_new(_("Stop and Restart"), FALSE, FALSE);
        gtk_widget_add_css_class(restart, "destructive-action");
        gtk_widget_set_halign(restart, GTK_ALIGN_FILL);
        g_signal_connect(restart, "clicked", G_CALLBACK(on_restart_clicked), job);
        GtkWidget *wait = gaudit_action_button_new(_("Wait"), FALSE, FALSE);
        gtk_widget_set_halign(wait, GTK_ALIGN_FILL);
        g_signal_connect(wait, "clicked", G_CALLBACK(on_wait_clicked), job);
        gtk_box_append(GTK_BOX(box), wait);
        gtk_box_append(GTK_BOX(box), restart);
        adw_status_page_set_child(job->status, box);
    }
    gaudit_session_attach(job->command, NULL, on_other_done, job);
}

AdwNavigationPage *gaudit_cached_report_page_new(const GauditTaskInfo *task)
{
    const char *command = NULL;
    GPtrArray *lines = gaudit_cache_lines(task, NULL);
    if (lines == NULL || (command = gaudit_cache_command(task)) == NULL)
        return NULL;
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
    adw_status_page_set_icon_name(status, "content-loading-symbolic");
    adw_status_page_set_title(status, _("Writing the report…"));
    /* Home's collections give simplified reports; Run on Parameters the report. */
    AdwNavigationPage *page = gaudit_page_wrap(GTK_WIDGET(status),
                                               gaudit_cache_full(task) ? _("Report")
                                                                       : _("Simplified Report"),
                                               "report");
    RunJob *job = g_new0(RunJob, 1);
    job->status = status;
    job->task = task;
    g_object_add_weak_pointer(G_OBJECT(status), (gpointer *)&job->status);
    ReportJob *rj = g_new0(ReportJob, 1);
    rj->job = job;
    rj->lines = g_ptr_array_ref(lines);
    gaudit_report_run(task, command, rj->lines, on_report, rj);
    return page;
}

static AdwNavigationPage *gaudit_run_page_new_with(const GauditTaskInfo *task, const char *command,
                                                   const char *const *args, gboolean fresh);

AdwNavigationPage *gaudit_run_page_new(const GauditTaskInfo *task)
{
    return gaudit_run_page_new_with(task, task->run_command, NULL, TRUE);
}

/* page 2 for command with args (NULL: Home's, simplified); fresh: the
 * plugin's own parameters as they are now. */
static AdwNavigationPage *gaudit_run_page_new_with(const GauditTaskInfo *task, const char *command,
                                                   const char *const *args, gboolean fresh)
{
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
#if ADW_CHECK_VERSION(1, 6, 0)
    g_autoptr(AdwSpinnerPaintable) spinner = adw_spinner_paintable_new(GTK_WIDGET(status));
    adw_status_page_set_paintable(status, GDK_PAINTABLE(spinner));
#else
    adw_status_page_set_icon_name(status, "content-loading-symbolic");
#endif
    adw_status_page_set_title(status, _(task->run_running));
    AdwNavigationPage *page = gaudit_page_wrap(GTK_WIDGET(status), _("Report"), "run");

    RunJob *job = g_new0(RunJob, 1);
    job->status = status;
    job->task = task;
    /* The parameters as they are now: changing them later is another run. */
    job->command = g_strdup(command);
    job->args = fresh ? gaudit_task_run_args(task) : args != NULL ? g_strdupv((char **)args) : NULL;
    g_object_add_weak_pointer(G_OBJECT(status), (gpointer *)&job->status);
    start_or_ask(job);
    return page;
}

AdwNavigationPage *gaudit_run_page_follow(const GauditTaskInfo *task)
{
    const char *command = gaudit_session_running_for(task->run_command);
    if (command == NULL)
        return NULL;
    return gaudit_run_page_new_with(task, command, gaudit_session_running_args(command), FALSE);
}

AdwNavigationPage *gaudit_run_page_again(const GauditTaskInfo *task)
{
    const char *command = gaudit_cache_command(task);
    if (command == NULL || gaudit_cache_full(task))
        return gaudit_run_page_new_with(task, command != NULL ? command : task->run_command,
                                        command != NULL ? gaudit_cache_args(task) : NULL,
                                        command == NULL);
    /* Home's collection: the same again, simplified. */
    return gaudit_run_page_new_with(task, command, NULL, FALSE);
}
