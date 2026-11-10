/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-firewall-text.h"
#include "gaudit-run-page.h"
#include "gaudit-session.h"
#include "gaudit/backend.h"
#include "gaudit-task-page.h"
#include "gaudit/run.h"

typedef struct {
    AdwStatusPage *status;  /* weak: the page may be left while the run goes on */
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

/* How to switch on each known firewall program: fixed commands, never
 * built from anything the system says. Which one applies is decided from
 * what the backend sees installed (presentation only; gAudit does not run
 * it, the user does). */
static const struct {
    const char *capability;
    const char *enable;
} firewall_tools[] = {
    { "ufw",       "sudo ufw enable" },
    { "firewalld", "sudo systemctl enable --now firewalld" },
};

static GtkWidget *small_note(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_add_css_class(label, "dim-label");
    gtk_widget_add_css_class(label, "caption");
    return label;
}

/* The manual way to switch the firewall on, under the warning. */
static void show_enable(RunJob *job)
{
    if (job->status == NULL)
        return;
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    const char *command = NULL;
    for (size_t i = 0; i < G_N_ELEMENTS(firewall_tools) && command == NULL; i++) {
        const gaudit_capability *cap = pkg->capability != NULL
            ? pkg->capability(firewall_tools[i].capability) : NULL;
        if (gaudit_capability_present(cap))
            command = firewall_tools[i].enable;
    }

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
        gtk_box_append(GTK_BOX(box), small_note(
            _("No known firewall program is installed. Install one first, for example ufw.")));
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

static void on_progress(gpointer user_data)
{
    RunJob *job = user_data;
    if (job->status != NULL) {
        adw_status_page_set_title(job->status, _("Checking the firewall…"));
        adw_status_page_set_description(job->status, NULL);
    }
}

static void on_run_done(gaudit_run_status status, const gaudit_firewall_report *result,
                        gpointer user_data)
{
    RunJob *job = user_data;
    if (status == GAUDIT_RUN_OK && result != NULL) {
        job->firewall = *result;
        show_firewall(job);
    } else if (status == GAUDIT_RUN_CANCELLED) {
        show(job, "dialog-information-symbolic", _("The check was cancelled"),
             _("No password was given, so the firewall was not checked."));
    } else if (status == GAUDIT_RUN_DENIED) {
        show(job, "dialog-password-symbolic", _("Not authorized"),
             _("The password was not accepted, or this account may not run administrator checks."));
    } else {
        show(job, "dialog-warning-symbolic", _("The check could not be completed"),
             _("Nothing is known about the firewall from this run."));
    }
    if (job->status != NULL)
        g_object_remove_weak_pointer(G_OBJECT(job->status), (gpointer *)&job->status);
    g_free(job);
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
    adw_status_page_set_title(status, _("Waiting for the password"));
    adw_status_page_set_description(status,
        _("Reading the firewall rules needs the administrator password."));
    AdwNavigationPage *page = gaudit_page_wrap(GTK_WIDGET(status), _(task->title), "run");

    RunJob *job = g_new0(RunJob, 1);
    job->status = status;
    g_object_add_weak_pointer(G_OBJECT(status), (gpointer *)&job->status);
    if (!gaudit_session_run(task->run_command, on_progress, on_run_done, job)) {
        show(job, "dialog-information-symbolic", _("Another check is running"),
             _("Wait until it has finished, then start this one again."));
        g_object_remove_weak_pointer(G_OBJECT(status), (gpointer *)&job->status);
        g_free(job);
    }
    return page;
}
