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
    GStrv args;             /* the run's parameters (the plugin's folders) */
    guint tick_id;          /* shows the progress of a run as the user */
    gint64 next_ask;        /* when to ask whether to go on (monotonic, µs) */
    GtkWidget *ask;         /* weak: the "keep going?" buttons, while shown */
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

/* --- Package integrity ------------------------------------------------- */

/* A dpkg package name, optionally with ":arch": [a-z0-9][a-z0-9+.-]+, so
 * it can go into a command without quoting. Anything else is left out of
 * the command (the finding is still listed). */
static gboolean plain_package(const char *name)
{
    const char *colon = strchr(name, ':');
    gsize len = colon != NULL ? (gsize)(colon - name) : strlen(name);
    if (len < 2 || !(g_ascii_islower(name[0]) || g_ascii_isdigit(name[0])))
        return FALSE;
    for (gsize i = 0; i < len; i++)
        if (!(g_ascii_islower(name[i]) || g_ascii_isdigit(name[i]) || strchr("+.-", name[i]) != NULL))
            return FALSE;
    if (colon != NULL)
        for (const char *c = colon + 1; *c != '\0'; c++)
            if (!(g_ascii_islower(*c) || g_ascii_isdigit(*c) || *c == '-'))
                return FALSE;
    return colon == NULL || colon[1] != '\0';
}

static GtkWidget *findings_group(const GauditRunResult *r, gaudit_integrity_file_kind kind,
                                 const char *title, const char *description)
{
    AdwPreferencesGroup *group = NULL;
    for (unsigned i = 0; i < r->n_files; i++) {
        if (r->files[i].kind != kind)
            continue;
        if (group == NULL) {
            group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
            adw_preferences_group_set_title(group, title);
            adw_preferences_group_set_description(group, description);
        }
        AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
        /* Paths and names come from the system: plain text only. */
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), r->files[i].path);
        adw_action_row_set_subtitle(row, r->files[i].package);
        adw_preferences_row_set_title_selectable(ADW_PREFERENCES_ROW(row), TRUE);
        adw_preferences_group_add(group, GTK_WIDGET(row));
    }
    return group != NULL ? GTK_WIDGET(group) : NULL;
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

static void show_integrity(RunJob *job, const GauditRunResult *r)
{
    const gaudit_integrity_report *ir = &r->integrity;
    g_autofree char *title = gaudit_run_result_title(r);
    const char *icon = ir->verdict == GAUDIT_VERDICT_OK ? "gaudit-status-high-symbolic"
                     : ir->verdict == GAUDIT_VERDICT_WARNING ? "gaudit-status-medium-symbolic"
                     : "gaudit-status-unknown-symbolic";
    /* Translators: "Checked <files> files from <packages> packages (<MB> MB) in <s> seconds." */
    g_autofree char *how = g_strdup_printf(_("Checked %lu files from %lu packages (%lu MB) in %u seconds."),
                                           ir->checked, ir->packages, ir->megabytes, ir->seconds);
    g_autofree char *description = ir->verdict == GAUDIT_VERDICT_OK
        ? g_strdup_printf("%s %s", how,
              /* Translators: Keep the meaning: no changes found is not proof. */
              _("This means no changes were found, not that the computer is proven clean."))
        : g_strdup(how);
    show(job, icon, title, description);
    if (job->status == NULL)
        return;

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    GtkWidget *changed = findings_group(r, GAUDIT_INTEGRITY_FILE_CHANGED, _("Changed"),
        _("The file differs from the one the package installed."));
    if (changed != NULL) {
        gtk_box_append(GTK_BOX(box), changed);
        /* Reinstalling puts the package's own files back. */
        g_autoptr(GString) cmd = g_string_new("sudo apt install --reinstall");
        g_autoptr(GHashTable) seen = g_hash_table_new(g_str_hash, g_str_equal);
        for (unsigned i = 0; i < r->n_files; i++) {
            const char *p = r->files[i].package;
            if (r->files[i].kind != GAUDIT_INTEGRITY_FILE_CHANGED || !plain_package(p)
                || !g_hash_table_add(seen, (gpointer)p))
                continue;
            g_string_append_printf(cmd, " %s", p);
        }
        if (g_hash_table_size(seen) > 0) {
            gtk_box_append(GTK_BOX(box), small_note(
                _("If you did not change these files yourself, put the packages' own files back "
                  "by reinstalling them:")));
            gtk_box_append(GTK_BOX(box), gaudit_command_field_new(cmd->str));
        }
    }
    GtkWidget *missing = findings_group(r, GAUDIT_INTEGRITY_FILE_MISSING, _("Missing"),
        _("The package installed the file, but it is gone."));
    if (missing != NULL)
        gtk_box_append(GTK_BOX(box), missing);
    GtkWidget *unreadable = findings_group(r, GAUDIT_INTEGRITY_FILE_UNREADABLE, _("Could not be read"),
        _("Even with administrator rights, these could not be read, so they were not checked."));
    if (unreadable != NULL)
        gtk_box_append(GTK_BOX(box), unreadable);
    unsigned long total = ir->changed + ir->missing + ir->unreadable;
    if (ir->shown < total) {
        g_autofree char *more = g_strdup_printf(_("Showing %u of %lu files."), ir->shown, total);
        gtk_box_append(GTK_BOX(box), small_note(more));
    }
    if (ir->bad_lines > 0) {
        g_autofree char *bad = g_strdup_printf(
            ngettext("%lu line in the packages' checksum lists could not be read.",
                     "%lu lines in the packages' checksum lists could not be read.", ir->bad_lines),
            ir->bad_lines);
        gtk_box_append(GTK_BOX(box), small_note(bad));
    }
    if (gtk_widget_get_first_child(box) == NULL) {
        g_object_ref_sink(box);
        g_object_unref(box);
        return;
    }
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(job->status, clamp);
}

/* --- The run ---------------------------------------------------------- */

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
    if (job->tick_id != 0)
        g_source_remove(job->tick_id);
    if (job->ask != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->ask), (gpointer *)&job->ask);
    if (job->status != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->status), (gpointer *)&job->status);
    g_strfreev(job->args);
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

static void on_report(GauditReport *report, gpointer user_data)
{
    ReportJob *rj = user_data;
    RunJob *job = rj->job;
    if (job->status != NULL && report != NULL) {
        FixData *d = g_new0(FixData, 1);
        d->task = job->task;
        d->lines = g_ptr_array_ref(rj->lines);
        gaudit_report_show(job->status, report, job->task->text_domain, fix_page, d, fix_data_free);
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
        gaudit_report_run(job->task, job->task->run_command, rj->lines, on_report, rj);
        return;
    } else if (status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_FIREWALL) {
        job->firewall = result->firewall;
        show_firewall(job);
    } else if (status == GAUDIT_RUN_OK && result != NULL
               && result->kind == GAUDIT_RESULT_INTEGRITY) {
        show_integrity(job, result);
    } else if (status == GAUDIT_RUN_CANCELLED && !job->task->needs_admin) {
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
    (void)user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    gaudit_session_cancel();  /* on_run_done says it was stopped */
}

static gboolean on_tick(gpointer user_data)
{
    RunJob *job = user_data;
    if (job->status == NULL || gaudit_session_running() == NULL) {
        job->tick_id = 0;
        return G_SOURCE_REMOVE;
    }
    const char *where = NULL;
    guint64 n = gaudit_session_progress(&where);
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
    if (job->task->needs_admin || job->tick_id != 0)
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
    (void)user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    gaudit_session_cancel();  /* on_other_done starts ours */
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
    const char *running = gaudit_session_running();
    if (running == NULL) {
        if (job->status != NULL)
            adw_status_page_set_title(job->status, job->task->needs_admin
                                      ? _("Waiting for the password") : _(job->task->run_running));
        if (!gaudit_session_run_args(job->task->run_command, (const char *const *)job->args,
                                     on_progress, on_run_done, job)) {
            show(job, "dialog-warning-symbolic", _("The check could not be started"), NULL);
            job_free(job);
            return;
        }
        watch_progress(job);
        return;
    }
    if (gaudit_session_running_is(job->task->run_command, (const char *const *)job->args)) {
        /* The same parameters: that run is this one. */
        if (job->status != NULL) {
            adw_status_page_set_title(job->status, _("In progress, processing…"));
            adw_status_page_set_description(job->status,
                _("This check was already running. Its result is shown here when it is done."));
        }
        gaudit_session_attach(NULL, on_run_done, job);
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
    gaudit_session_attach(NULL, on_other_done, job);
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

AdwNavigationPage *gaudit_run_page_new(const GauditTaskInfo *task)
{
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
#if ADW_CHECK_VERSION(1, 6, 0)
    g_autoptr(AdwSpinnerPaintable) spinner = adw_spinner_paintable_new(GTK_WIDGET(status));
    adw_status_page_set_paintable(status, GDK_PAINTABLE(spinner));
#else
    adw_status_page_set_icon_name(status, "content-loading-symbolic");
#endif
    if (task->needs_admin) {
        adw_status_page_set_title(status, _("Waiting for the password"));
        adw_status_page_set_description(status, _(task->run_waiting));
    } else {
        adw_status_page_set_title(status, _(task->run_running));
    }
    AdwNavigationPage *page = gaudit_page_wrap(GTK_WIDGET(status), _("Report"), "run");

    RunJob *job = g_new0(RunJob, 1);
    job->status = status;
    job->task = task;
    /* The parameters as they are now: changing them later is another run. */
    job->args = gaudit_task_run_args(task);
    g_object_add_weak_pointer(G_OBJECT(status), (gpointer *)&job->status);
    start_or_ask(job);
    return page;
}
