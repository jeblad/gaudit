/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-window.h"
#include "gaudit-crossfade.h"
#include "gaudit-category.h"
#include "gaudit-sourceless-page.h"
#include "gaudit-firewall-text.h"
#include "gaudit-session.h"
#include "gaudit-task.h"
#include "gaudit-task-page.h"

struct _GauditWindow {
    AdwApplicationWindow parent_instance;

    GSettings *settings;  /* NULL when the schema is not installed */
    GtkWidget *elevated_marker;  /* red disc before the title */

    AdwNavigationSplitView *split;
    GtkListBox *sidebar;
    AdwNavigationView *content;

    const gaudit_pkg_backend *pkg;
    gboolean have_status;  /* every row has its answer */
    gaudit_probe_result probes[GAUDIT_PROBE_COUNT];
    gboolean received[GAUDIT_PROBE_COUNT];
    gaudit_verdict worst;

    /* Widgets on the Home page while it exists (weak pointers), so rows
     * can be filled in one by one as their answers arrive. */
    AdwStatusPage *home_status;
    AdwActionRow *rows[GAUDIT_PROBE_COUNT];

    /* Home's checks that need the password, by task index. Results stay
     * after the rights have ended. They run together, so one time for the
     * group. */
    struct {
        int state;  /* ELEVATED_NONE, _RUNNING, _DONE */
        gboolean have;  /* a result, from this run or an earlier one */
        gaudit_firewall_report fw;
    } elevated[GAUDIT_WINDOW_MAX_TASKS];
    char elevated_when[16];  /* when the shown results were checked; "" before any */
    gboolean elevated_running;
    const char *elevated_note;  /* static, translated: why the last run gave nothing */
    AdwPreferencesGroup *elevated_group;  /* weak */
    GPtrArray *elevated_rows;   /* the rows now in elevated_group */
};

G_DEFINE_FINAL_TYPE(GauditWindow, gaudit_window, ADW_TYPE_APPLICATION_WINDOW)

enum { ELEVATED_NONE, ELEVATED_RUNNING, ELEVATED_DONE };

static void navigate(GauditWindow *self, int index, gboolean show_content);

/* --- Home ----------------------------------------------------------------- */

/* Whether the checks that need the password have all been run and passed.
 * Their results stay until the next run or restart. */
static gboolean strict_passed(GauditWindow *self)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    gboolean any = FALSE;
    for (gsize i = 0; i < n_tasks && i < GAUDIT_WINDOW_MAX_TASKS; i++) {
        if (!tasks[i].home_elevated)
            continue;
        if (!self->elevated[i].have || self->elevated[i].fw.verdict != GAUDIT_VERDICT_OK)
            return FALSE;
        any = TRUE;
    }
    return any;
}

/* The shields have gAudit's own names, so no icon theme can replace them:
 * their shapes carry the meaning, not only their colour (Yaru, for one,
 * draws every level as the same shield in different colours). */
static void set_summary(AdwStatusPage *status, gboolean have_status, gboolean strict,
                        gaudit_verdict worst)
{
    const char *icon, *title, *description;

    if (!have_status) {
        /* The orchestrator is still working. */
#if ADW_CHECK_VERSION(1, 6, 0)
        g_autoptr(AdwSpinnerPaintable) spinner = adw_spinner_paintable_new(GTK_WIDGET(status));
        adw_status_page_set_paintable(status, GDK_PAINTABLE(spinner));
        icon = NULL;
#else
        icon = "content-loading-symbolic";
#endif
        title = _("Checking…");
        description = _("Looking at the status of this computer.");
    } else {
        switch (worst) {
        case GAUDIT_VERDICT_OK:
            icon = strict ? "gaudit-status-ok-symbolic" : "gaudit-status-high-symbolic";
            title = _("No signs of problems found");
            /* Translators: Keep the meaning: a clean result is not a guarantee. */
            description = _("This does not prove the computer is safe, "
                            "only that the checks found nothing wrong.");
            break;
        case GAUDIT_VERDICT_WARNING:
            icon = "gaudit-status-medium-symbolic";
            title = _("Some things need attention");
            description = NULL;
            break;
        case GAUDIT_VERDICT_CRITICAL:
            icon = "gaudit-status-low-symbolic";
            title = _("Serious problems found");
            description = NULL;
            break;
        case GAUDIT_VERDICT_UNKNOWN:
        default:
            icon = "gaudit-status-unknown-symbolic";
            title = _("Some checks could not be completed");
            description = NULL;
            break;
        }
    }

    /* A shield that changes once the status is in (e.g. from "the simple
     * checks passed" to "every check passed" after the password checks)
     * fades into the new one; the first shield after the spinner just appears. */
    const char *shown = g_object_get_data(G_OBJECT(status), "gaudit-shield");
    if (icon != NULL && shown != NULL && have_status && g_strcmp0(shown, icon) != 0) {
        g_autoptr(GdkPaintable) fade = gaudit_crossfade_new(GTK_WIDGET(status), shown, icon,
                                                            128, 700);
        adw_status_page_set_paintable(status, fade);
    } else if (icon != NULL) {
        adw_status_page_set_icon_name(status, icon);
    }
    /* The names are static strings. */
    g_object_set_data(G_OBJECT(status), "gaudit-shield", (gpointer)icon);
    adw_status_page_set_title(status, title);
    adw_status_page_set_description(status, description);
}

/* Icon for a verdict. The meaning is also given as an accessible label,
 * so it never depends on colour alone. */
static GtkWidget *verdict_icon(gaudit_verdict verdict)
{
    const char *icon, *css, *label;

    switch (verdict) {
    case GAUDIT_VERDICT_OK:
        icon = "emblem-ok-symbolic";      css = "success";   label = _("OK");
        break;
    case GAUDIT_VERDICT_WARNING:
        icon = "dialog-warning-symbolic"; css = "warning";   label = _("Needs attention");
        break;
    case GAUDIT_VERDICT_CRITICAL:
        icon = "dialog-error-symbolic";   css = "error";     label = _("Serious");
        break;
    case GAUDIT_VERDICT_UNKNOWN:
    default:
        icon = "dialog-question-symbolic"; css = "dim-label"; label = _("Unknown");
        break;
    }

    GtkWidget *image = gtk_image_new_from_icon_name(icon);
    gtk_widget_add_css_class(image, css);
    gtk_widget_set_tooltip_text(image, label);
    gtk_accessible_update_property(GTK_ACCESSIBLE(image),
                                   GTK_ACCESSIBLE_PROPERTY_LABEL, label, -1);
    return image;
}

/* Title and subtitle for a probe result. The subtitle is newly allocated. */
static const char *probe_title(const gaudit_probe_result *r);

static const char *probe_text(const gaudit_probe_result *r, char **subtitle)
{
    if (r->unsupported) {
        *subtitle = g_strdup(_("Not supported on this system yet"));
        return probe_title(r);
    }
    switch (r->kind) {
    case GAUDIT_PROBE_PACKAGE_SYSTEM: {
        char name[128], full[8];
        gaudit_system_describe(NULL, 0, name, sizeof name, full, sizeof full);
        /* Translators: "This looks like Ubuntu, but its package system (dpkg/apt) was not found". */
        *subtitle = g_strdup_printf(_("This looks like %s, but its package system (%s) was not found"),
                                    name[0] != '\0' ? name : _("a known distribution"),
                                    r->detail[0] != '\0' ? r->detail : "?");
        return _("Package system");
    }

    case GAUDIT_PROBE_SNAP:
        if (r->missing_capability[0] != '\0') {
            *subtitle = g_strdup(_("Software needed to check snaps is missing"));
        } else if (r->service_down) {
            *subtitle = g_strdup(_("The snap service is not running, so snaps are not updated"));
        } else if (r->verdict == GAUDIT_VERDICT_UNKNOWN) {
            *subtitle = g_strdup(_("Could not check the snaps"));
        } else {
            const char *parts[6];
            int n = 0;
            g_autofree char *hold = NULL, *age = NULL, *held = NULL, *devmode = NULL, *classic = NULL;
            if (r->until_epoch > 0) {
                g_autoptr(GDateTime) until = g_date_time_new_from_unix_local(r->until_epoch);
                g_autofree char *date = until != NULL ? g_date_time_format(until, "%x") : g_strdup("?");
                /* Translators: %s is a date. */
                hold = g_strdup_printf(_("Automatic updates are paused until %s"), date);
                parts[n++] = hold;
            }
            if (r->age_seconds > GAUDIT_PROBE_SNAP_MAX_AGE) {
                gint64 days = r->age_seconds / (24 * 60 * 60);
                age = g_strdup_printf(ngettext("Last updated %d day ago", "Last updated %d days ago",
                                               (unsigned long)days),
                                      (int)MIN(days, G_MAXINT));
                parts[n++] = age;
            }
            if (r->extra_count > 0) {
                held = g_strdup_printf(ngettext("%u snap is held back from updates",
                                                "%u snaps are held back from updates",
                                                r->extra_count),
                                       r->extra_count);
                parts[n++] = held;
            }
            if (r->count > 0) {
                devmode = g_strdup_printf(ngettext("%u snap runs in developer mode, without a working sandbox",
                                                   "%u snaps run in developer mode, without a working sandbox",
                                                   r->count),
                                          r->count);
                parts[n++] = devmode;
            }
            if (n == 0)
                parts[n++] = _("Snaps are updated automatically");
            if (r->info_count > 0) {
                classic = g_strdup_printf(ngettext("%u snap runs without a sandbox by design (classic)",
                                                   "%u snaps run without a sandbox by design (classic)",
                                                   r->info_count),
                                          r->info_count);
                parts[n++] = classic;
            }
            parts[n] = NULL;
            *subtitle = g_strjoinv(" · ", (char **)parts);
        }
        return _("Snap apps");

    case GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS: {
        g_autoptr(GPtrArray) names = g_ptr_array_new();
        for (int s = 0; s < GAUDIT_PKGSYS_COUNT; s++)
            if (r->mask & (1u << s))
                g_ptr_array_add(names, (gpointer)gaudit_package_system_label((gaudit_package_system)s));
        g_ptr_array_add(names, NULL);
        g_autofree char *list = g_strjoinv(", ", (char **)names->pdata);
        /* Translators: %s is a list of package systems, e.g. "rpm, Nix". */
        *subtitle = g_strdup_printf(_("Packages managed by %s are not checked"), list);
        return _("Other package systems");
    }

    case GAUDIT_PROBE_ANTIVIRUS:
        *subtitle = g_strdup(r->verdict == GAUDIT_VERDICT_OK
                             ? _("An antivirus program is installed")
                             : _("No antivirus program found"));
        return _("Antivirus");

    case GAUDIT_PROBE_FIREWALL:
        *subtitle = g_strdup(r->verdict == GAUDIT_VERDICT_OK
                             ? _("A firewall is installed")
                             : _("No firewall found"));
        return _("Firewall");

    case GAUDIT_PROBE_LISTENING:
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN) {
            *subtitle = g_strdup(_("Could not find out which services listen on the network"));
        } else if (r->count == 0) {
            *subtitle = g_strdup(_("No services listen for connections from the network"));
        } else {
            g_autofree char *how_many = g_strdup_printf(
                ngettext("%u service listens for connections from the network.",
                         "%u services listen for connections from the network.", r->count),
                r->count);
            g_autofree char *whose = r->extra_count == 0
                ? g_strdup(_("None of them run under your account."))
                : g_strdup_printf(ngettext("%u of them runs under your account.",
                                           "%u of them run under your account.", r->extra_count),
                                  r->extra_count);
            /* Translators: Home cannot see the firewall; page 2 can. */
            *subtitle = g_strdup_printf("%s %s %s", how_many, whose,
                _("The firewall check shows whether they can be reached."));
        }
        return _("Network services");

    case GAUDIT_PROBE_SECURITY_SOURCE:
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN)
            *subtitle = g_strdup(_("Could not find out where security updates come from"));
        else if (r->verdict == GAUDIT_VERDICT_OK)
            *subtitle = g_strdup(_("Security updates come directly from the distribution"));
        else
            /* Translators: %s is a host name, e.g. no.archive.ubuntu.com. */
            *subtitle = g_strdup_printf(_("Security updates come from %s, a mirror that may lag behind"),
                                        r->text[0] != '\0' ? r->text : "?");
        return _("Source of security updates");

    case GAUDIT_PROBE_PRIVATE_FILES:
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN)
            *subtitle = g_strdup(_("Could not check the private files"));
        else if (r->count == 0)
            *subtitle = g_strdup(_("Private files and folders are protected"));
        else
            /* Translators: %s is the first file or folder, e.g. ~/.ssh/id_ed25519. */
            *subtitle = g_strdup_printf(ngettext("%u private file or folder can be reached by others: %s",
                                                 "%u private files or folders can be reached by others, e.g. %s",
                                                 r->count),
                                        r->count, r->text);
        return _("Private files");

    case GAUDIT_PROBE_PACKAGE_INDEX:
        /* When the package lists were refreshed, which is not the same as
         * packages having been upgraded. */
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN) {
            *subtitle = g_strdup(_("Could not find out when updates were last checked for"));
        } else {
            gint64 days = r->age_seconds / (24 * 60 * 60);
            if (days == 0)
                *subtitle = g_strdup(_("Last checked today"));
            else
                *subtitle = g_strdup_printf(ngettext("Last checked %d day ago",
                                                     "Last checked %d days ago",
                                                     (unsigned long)days),
                                            (int)MIN(days, G_MAXINT));
        }
        return _("Checking for updates");

    case GAUDIT_PROBE_PENDING_UPGRADES:
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN)
            *subtitle = g_strdup(_("Could not find out whether updates are waiting"));
        else if (r->count == 0)
            *subtitle = g_strdup(_("No updates are waiting"));
        else
            *subtitle = g_strdup_printf(ngettext("%u update is waiting to be installed",
                                                 "%u updates are waiting to be installed",
                                                 r->count),
                                        r->count);
        return _("Pending updates");

    case GAUDIT_PROBE_OBSOLETE_PACKAGES:
        if (r->verdict == GAUDIT_VERDICT_UNKNOWN)
            *subtitle = g_strdup(_("Could not find out where the installed packages come from"));
        else if (r->count == 0)
            *subtitle = g_strdup(_("All packages come from a software source"));
        else
            *subtitle = g_strdup_printf(ngettext("%u package is no longer offered by any software source",
                                                 "%u packages are no longer offered by any software source",
                                                 r->count),
                                        r->count);
        return _("Packages without a source");

    case GAUDIT_PROBE_AUTO_UPDATES:
        *subtitle = g_strdup(r->verdict == GAUDIT_VERDICT_OK
                             ? _("Updates are installed automatically")
                             : r->verdict == GAUDIT_VERDICT_WARNING
                             ? _("Automatic updates are switched off")
                             : _("Could not find out whether automatic updates are switched on"));
        return _("Automatic updates");

    case GAUDIT_PROBE_FLATPAK:
        if (r->missing_capability[0] != '\0') {
            *subtitle = g_strdup(_("Software needed to check Flatpak apps is missing"));
        } else if (r->verdict == GAUDIT_VERDICT_UNKNOWN) {
            *subtitle = g_strdup(_("Could not check the Flatpak apps"));
        } else if (r->count == 0 && r->extra_count == 0 && r->info_count == 0) {
            *subtitle = g_strdup(_("No apps use runtimes without security updates"));
        } else {
            /* Apps on end-of-life runtimes are fixed by their developers;
             * unused runtimes can be removed by the user. */
            g_autofree char *apps = r->count == 0 ? NULL
                : g_strdup_printf(ngettext("%u app uses a runtime without security updates",
                                           "%u apps use runtimes without security updates",
                                           r->count),
                                  r->count);
            g_autofree char *unused = r->extra_count == 0 ? NULL
                : g_strdup_printf(ngettext("%u unused outdated runtime can be removed",
                                           "%u unused outdated runtimes can be removed",
                                           r->extra_count),
                                  r->extra_count);
            g_autofree char *kept = r->info_count == 0 ? NULL
                : g_strdup_printf(ngettext("%u outdated runtime is kept but not used by any app",
                                           "%u outdated runtimes are kept but not used by any app",
                                           r->info_count),
                                  r->info_count);
            const char *parts[4];
            int n = 0;
            if (apps != NULL)
                parts[n++] = apps;
            if (unused != NULL)
                parts[n++] = unused;
            if (kept != NULL)
                parts[n++] = kept;
            parts[n] = NULL;
            *subtitle = g_strjoinv(" · ", (char **)parts);
        }
        return _("Flatpak apps");

    case GAUDIT_PROBE_COUNT:
    default:
        break;
    }
    *subtitle = NULL;
    return r->id;
}

static const char *probe_title(const gaudit_probe_result *r)
{
    g_autofree char *ignored = NULL;
    gaudit_probe_result copy = *r;
    copy.unsupported = 0;
    copy.verdict = GAUDIT_VERDICT_UNKNOWN;
    copy.missing_capability[0] = '\0';
    return probe_text(&copy, &ignored);
}

static void on_missing_row_activated(AdwActionRow *row, gpointer user_data)
{
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    if (g_object_get_data(G_OBJECT(row), "gaudit-sourceless") != NULL) {
        adw_navigation_view_push(self->content, gaudit_sourceless_page_new());
        return;
    }
    const GauditCategory *category = g_object_get_data(G_OBJECT(row), "gaudit-category");
    if (category != NULL) {
        /* Nothing in the category is installed: choose one. */
        adw_navigation_view_push(self->content, gaudit_category_page_new(category, self->pkg));
        return;
    }
    const char *capability = g_object_get_data(G_OBJECT(row), "gaudit-capability");
    if (capability == NULL)
        return;  /* nothing missing (or still checking) */
    const gaudit_capability *cap = self->pkg->capability ? self->pkg->capability(capability) : NULL;
    if (cap == NULL)
        return;
    adw_navigation_view_push(self->content,
        gaudit_missing_software_page_new(self->pkg, adw_preferences_row_get_title(ADW_PREFERENCES_ROW(row)),
                                         cap->packages));
}

static void on_home_row_activated(AdwActionRow *row, gpointer user_data)
{
    int index = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "gaudit-index"));
    navigate(GAUDIT_WINDOW(user_data), index, TRUE);
}

/* *slot = obj as a weak pointer, letting go of what it pointed to before
 * (a weak pointer is cleared on finalize whatever the slot holds then). */
static void set_weak(gpointer slot, gpointer obj)
{
    GObject **p = slot;
    if (*p != NULL)
        g_object_remove_weak_pointer(*p, (gpointer *)p);
    *p = obj;
    if (obj != NULL)
        g_object_add_weak_pointer(obj, (gpointer *)p);
}

static GtkWidget *row_spinner(void)
{
#if ADW_CHECK_VERSION(1, 6, 0)
    return adw_spinner_new();
#else
    GtkWidget *spinner = gtk_spinner_new();
    gtk_spinner_start(GTK_SPINNER(spinner));
    return spinner;
#endif
}

/* The task a Home row stands for, as its index in the task list; -1 for
 * none. */
static int task_for_probe(const char *probe_id)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; probe_id != NULL && i < n_tasks; i++)
        if (g_strcmp0(tasks[i].home_probe, probe_id) == 0)
            return (int)i;
    return -1;
}

static void on_task_button_clicked(GtkButton *button, gpointer user_data)
{
    int index = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "gaudit-index"));
    navigate(GAUDIT_WINDOW(user_data), index, TRUE);
}

/* Shows row k as the state is now: a spinner while its answer is on its
 * way, then the result; hidden when the check does not apply here. */
static void fill_row(GauditWindow *self, int k)
{
    AdwActionRow *row = self->rows[k];
    if (row == NULL)
        return;
    const gaudit_probe_result *probe = &self->probes[k];

    GtkWidget *old = g_object_get_data(G_OBJECT(row), "gaudit-prefix");
    if (old != NULL)
        adw_action_row_remove(row, old);
    old = g_object_get_data(G_OBJECT(row), "gaudit-suffix");
    if (old != NULL)
        adw_action_row_remove(row, old);
    g_object_set_data(G_OBJECT(row), "gaudit-suffix", NULL);
    old = g_object_get_data(G_OBJECT(row), "gaudit-task-button");
    if (old != NULL)
        adw_action_row_remove(row, old);
    g_object_set_data(G_OBJECT(row), "gaudit-task-button", NULL);
    g_object_set_data(G_OBJECT(row), "gaudit-capability", NULL);
    g_object_set_data(G_OBJECT(row), "gaudit-category", NULL);
    g_object_set_data(G_OBJECT(row), "gaudit-sourceless", NULL);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);

    if (!self->received[k]) {
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), probe_title(probe));
        adw_action_row_set_subtitle(row, _("Checking…"));
        GtkWidget *spinner = row_spinner();
        adw_action_row_add_prefix(row, spinner);
        g_object_set_data(G_OBJECT(row), "gaudit-prefix", spinner);
        gtk_widget_set_visible(GTK_WIDGET(row), TRUE);
        return;
    }
    if (!probe->applicable) {
        g_object_set_data(G_OBJECT(row), "gaudit-prefix", NULL);
        gtk_widget_set_visible(GTK_WIDGET(row), FALSE);
        return;
    }

    g_autofree char *subtitle = NULL;
    const char *title = probe_text(probe, &subtitle);
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    adw_action_row_set_subtitle(row, subtitle);
    GtkWidget *icon = verdict_icon(probe->verdict);
    adw_action_row_add_prefix(row, icon);
    g_object_set_data(G_OBJECT(row), "gaudit-prefix", icon);

    /* A task that goes deeper than this row: a button to it. */
    int task_index = task_for_probe(probe->id);
    if (task_index >= 0) {
        gsize n_tasks;
        const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
        /* The plugin's own icon, as in the sidebar: this leads to that
         * plugin, unlike the plain arrow of rows that open a subpage. */
        GtkWidget *button = gtk_button_new_from_icon_name(tasks[task_index].icon);
        gtk_widget_add_css_class(button, "flat");
        gtk_widget_add_css_class(button, "circular");
        gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
        const char *tip = _(tasks[task_index].home_tooltip != NULL
                            ? tasks[task_index].home_tooltip : tasks[task_index].title);
        gtk_widget_set_tooltip_text(button, tip);
        gtk_accessible_update_property(GTK_ACCESSIBLE(button), GTK_ACCESSIBLE_PROPERTY_LABEL, tip, -1);
        g_object_set_data(G_OBJECT(button), "gaudit-index", GINT_TO_POINTER(task_index + 1));
        g_signal_connect(button, "clicked", G_CALLBACK(on_task_button_clicked), self);
        adw_action_row_add_suffix(row, button);
        g_object_set_data(G_OBJECT(row), "gaudit-task-button", button);
    }

    /* Packages without a source: the row leads to the list, where the
     * backend can give one. */
    if (probe->kind == GAUDIT_PROBE_OBSOLETE_PACKAGES && probe->count > 0
        && probe->verdict != GAUDIT_VERDICT_UNKNOWN && self->pkg->sourceless_packages != NULL) {
        GtkWidget *next = gtk_image_new_from_icon_name("go-next-symbolic");
        adw_action_row_add_suffix(row, next);
        g_object_set_data(G_OBJECT(row), "gaudit-suffix", next);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
        g_object_set_data(G_OBJECT(row), "gaudit-sourceless", GINT_TO_POINTER(1));
        gtk_widget_set_visible(GTK_WIDGET(row), TRUE);
        return;
    }

    /* A category with nothing installed (no firewall, no antivirus): the
     * row leads to choosing one. */
    const GauditCategory *category = gaudit_category_for_probe(probe->id);
    if (category != NULL && probe->verdict == GAUDIT_VERDICT_WARNING) {
        GtkWidget *next = gtk_image_new_from_icon_name("go-next-symbolic");
        adw_action_row_add_suffix(row, next);
        g_object_set_data(G_OBJECT(row), "gaudit-suffix", next);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
        g_object_set_data(G_OBJECT(row), "gaudit-category", (gpointer)category);
        gtk_widget_set_visible(GTK_WIDGET(row), TRUE);
        return;
    }

    const gaudit_capability *missing = probe->missing_capability[0] == '\0' || self->pkg->capability == NULL
        ? NULL : self->pkg->capability(probe->missing_capability);
    /* Only lead on when the backend knows which packages to install. */
    if (missing != NULL && missing->packages != NULL && missing->packages[0] != NULL) {
        GtkWidget *next = gtk_image_new_from_icon_name("go-next-symbolic");
        adw_action_row_add_suffix(row, next);
        g_object_set_data(G_OBJECT(row), "gaudit-suffix", next);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
        g_object_set_data(G_OBJECT(row), "gaudit-capability", (gpointer)probe->missing_capability);
    }
    gtk_widget_set_visible(GTK_WIDGET(row), TRUE);
}

/* --- Home: checks that need the password ---------------------------------- */

static void on_run_elevated_clicked(GtkButton *button, gpointer user_data)
{
    (void)user_data;
    gtk_widget_activate_action(GTK_WIDGET(button), "app.run-elevated", NULL);
}

static void fill_elevated(GauditWindow *self)
{
    AdwPreferencesGroup *group = self->elevated_group;
    if (group == NULL)
        return;
    for (guint i = 0; i < self->elevated_rows->len; i++)
        adw_preferences_group_remove(group, g_ptr_array_index(self->elevated_rows, i));
    g_ptr_array_set_size(self->elevated_rows, 0);

    gboolean any_done = FALSE;
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks && i < GAUDIT_WINDOW_MAX_TASKS; i++) {
        if (!tasks[i].home_elevated || self->elevated[i].state == ELEVATED_NONE)
            continue;
        AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), _(tasks[i].title));
        if (self->elevated[i].state == ELEVATED_RUNNING) {
            adw_action_row_add_prefix(row, row_spinner());
            adw_action_row_set_subtitle(row, _("Checking…"));
        } else {
            any_done = TRUE;
            const char *icon;
            g_autofree char *title = NULL, *description = NULL;
            gaudit_firewall_text(&self->elevated[i].fw, &icon, &title, &description);
            adw_action_row_set_subtitle(row, title);
            adw_action_row_add_prefix(row, verdict_icon(self->elevated[i].fw.verdict));
            GtkWidget *button = gtk_button_new_from_icon_name(tasks[i].icon);
            gtk_widget_add_css_class(button, "flat");
            gtk_widget_add_css_class(button, "circular");
            gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
            const char *tip = _(tasks[i].home_tooltip != NULL ? tasks[i].home_tooltip : tasks[i].title);
            gtk_widget_set_tooltip_text(button, tip);
            gtk_accessible_update_property(GTK_ACCESSIBLE(button), GTK_ACCESSIBLE_PROPERTY_LABEL, tip, -1);
            g_object_set_data(G_OBJECT(button), "gaudit-index", GINT_TO_POINTER((int)i + 1));
            g_signal_connect(button, "clicked", G_CALLBACK(on_task_button_clicked), self);
            adw_action_row_add_suffix(row, button);
        }
        adw_preferences_group_add(group, GTK_WIDGET(row));
        g_ptr_array_add(self->elevated_rows, row);
    }

    GtkWidget *run = adw_preferences_group_get_header_suffix(group);
    if (run != NULL) {
        gtk_button_set_label(GTK_BUTTON(run), any_done ? _("Run Again") : _("Run These Checks"));
        gtk_widget_set_sensitive(run, !self->elevated_running);
    }
    /* One time for the group, never per row. */
    g_autofree char *description = NULL;
    if (self->elevated_note != NULL && any_done)
        /* Translators: "<why nothing new> The results shown are from <time>." */
        description = g_strdup_printf(_("%s The results shown are from %s."),
                                      self->elevated_note, self->elevated_when);
    else if (self->elevated_note != NULL)
        description = g_strdup(self->elevated_note);
    else if (any_done && !self->elevated_running)
        /* Translators: %s is a time, e.g. 14:32. */
        description = g_strdup_printf(_("Checked at %s."), self->elevated_when);
    else
        description = g_strdup(_("A closer look with administrator rights. Asks for your password."));
    adw_preferences_group_set_description(group, description);
}

static void build_elevated(GauditWindow *self, GtkWidget *box)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    gboolean any = FALSE;
    for (gsize i = 0; i < n_tasks; i++)
        any |= tasks[i].home_elevated;
    if (!any)
        return;
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(group, _("Checks that need your password"));
    GtkWidget *run = gtk_button_new_with_label(_("Run These Checks"));
    gtk_widget_add_css_class(run, "flat");
    gtk_widget_set_valign(run, GTK_ALIGN_CENTER);
    g_signal_connect(run, "clicked", G_CALLBACK(on_run_elevated_clicked), NULL);
    adw_preferences_group_set_header_suffix(group, run);
    g_ptr_array_set_size(self->elevated_rows, 0);  /* rows of an earlier page are gone */
    set_weak(&self->elevated_group, group);
    fill_elevated(self);
    gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
}

static AdwNavigationPage *build_home(GauditWindow *self)
{
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
    set_summary(status, self->have_status, strict_passed(self), self->worst);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    set_weak(&self->home_status, status);

    {
        /* Host and distribution come from the system and are shown as
         * plain text, never as markup. */
        char host[256], distro[256], full[256];
        gaudit_system_describe(host, sizeof host, distro, sizeof distro, full, sizeof full);
        /* How gAudit treats the system, i.e. which backend does the checks.
         * Not read from the distribution, so never called its "family". */
        const char *checked = g_strcmp0(self->pkg->name, "debian") == 0 ? _("checked as Debian")
                            : g_strcmp0(self->pkg->name, "fedora") == 0 ? _("checked as Fedora")
                            : g_strcmp0(self->pkg->name, "arch") == 0 ? _("checked as Arch")
                            : _("general checks only");
        /* The version matters (releases go out of support), so the full
         * name is shown when os-release has one. */
        const char *name = full[0] != '\0' ? full : distro[0] != '\0' ? distro : _("Unknown system");
        /* Translators: "<system> · <how gAudit checks it>",
         * e.g. "Ubuntu 26.04 LTS · checked as Debian". */
        g_autofree char *system = g_strdup_printf(_("%s · %s"), name, checked);

        AdwPreferencesGroup *machine = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(machine, _("This computer"));
        AdwActionRow *id_row = ADW_ACTION_ROW(adw_action_row_new());
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(id_row), FALSE);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(id_row),
                                      host[0] != '\0' ? host : _("Unknown host name"));
        adw_action_row_set_subtitle(id_row, system);
        adw_preferences_group_add(machine, GTK_WIDGET(id_row));
        gtk_box_append(GTK_BOX(box), GTK_WIDGET(machine));

        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(group, _("Checks without a password"));
        for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
            AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
            /* Subtitles carry data from the system: never interpret markup. */
            adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
            g_signal_connect(row, "activated", G_CALLBACK(on_missing_row_activated), self);
            set_weak(&self->rows[k], row);
            fill_row(self, k);
            adw_preferences_group_add(group, GTK_WIDGET(row));
        }
        gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
    }

    build_elevated(self, box);

    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    /* Tasks without a Home row of their own; the others are reached from
     * their row, so they are not listed twice. */
    gsize n_listed = 0;
    for (gsize i = 0; i < n_tasks; i++)
        if (tasks[i].home_probe == NULL)
            n_listed++;
    if (n_listed > 0) {
        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(group, _("Checks"));
        for (gsize i = 0; i < n_tasks; i++) {
            const GauditTaskInfo *task = &tasks[i];
            if (task->home_probe != NULL)
                continue;
            g_autoptr(GPtrArray) missing = gaudit_task_missing_packages(task, self->pkg);
            const char *state = missing == NULL ? _("Not available on this system")
                              : missing->len > 0 ? _("Software is missing")
                              : _("Not run yet");

            AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
            adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), _(task->title));
            adw_action_row_set_subtitle(row, state);
            adw_action_row_add_prefix(row, gtk_image_new_from_icon_name(task->icon));
            adw_action_row_add_suffix(row, gtk_image_new_from_icon_name("go-next-symbolic"));
            gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
            g_object_set_data(G_OBJECT(row), "gaudit-index", GINT_TO_POINTER((int)i + 1));
            g_signal_connect(row, "activated", G_CALLBACK(on_home_row_activated), self);
            adw_preferences_group_add(group, GTK_WIDGET(row));
        }
        gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
    }

    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(status, clamp);

    return gaudit_page_wrap(GTK_WIDGET(status), _("Home"), "home");
}

/* --- Navigation ----------------------------------------------------------- */

/* index 0 is Home, index i > 0 is task i - 1. */
static void navigate(GauditWindow *self, int index, gboolean show_content)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    g_return_if_fail(index >= 0 && (gsize)index <= n_tasks);

    AdwNavigationPage *page = index == 0
        ? build_home(self)
        : gaudit_task_page_new(&tasks[index - 1], self->pkg);
    adw_navigation_view_replace(self->content, &page, 1);

    GtkListBoxRow *row = gtk_list_box_get_row_at_index(self->sidebar, index);
    if (gtk_list_box_get_selected_row(self->sidebar) != row)
        gtk_list_box_select_row(self->sidebar, row);

    if (show_content)
        adw_navigation_split_view_set_show_content(self->split, TRUE);
}

static void on_sidebar_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer user_data)
{
    (void)box;
    navigate(GAUDIT_WINDOW(user_data), gtk_list_box_row_get_index(row), TRUE);
}

/* subtitle may be NULL. */
static GtkWidget *sidebar_row(const char *icon, const char *title, const char *subtitle)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    GtkWidget *image = gtk_image_new_from_icon_name(icon);
    gtk_widget_add_css_class(image, "sidebar-icon");
    /* Centre in both directions so the circle is never stretched to the
     * row height. */
    gtk_widget_set_valign(image, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(image, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), image);

    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_valign(text, GTK_ALIGN_CENTER);
    GtkWidget *label = gtk_label_new(title);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_box_append(GTK_BOX(text), label);
    if (subtitle != NULL) {
        GtkWidget *sub = gtk_label_new(subtitle);
        gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(sub), PANGO_ELLIPSIZE_END);
        gtk_widget_add_css_class(sub, "caption");
        gtk_widget_add_css_class(sub, "dim-label");
        gtk_box_append(GTK_BOX(text), sub);
    }
    gtk_box_append(GTK_BOX(box), text);

    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    return row;
}

static GtkWidget *primary_menu_button(void)
{
    GMenu *section = g_menu_new();
    g_menu_append(section, _("_Preferences"), "app.preferences");
    g_menu_append(section, _("_Keyboard Shortcuts"), "app.shortcuts");
    /* Translators: %s is the application name, which is not translated. */
    g_autofree char *about = g_strdup_printf(_("_About %s"), GAUDIT_APP_NAME);
    g_menu_append(section, about, "app.about");

    GMenu *menu = g_menu_new();
    g_menu_append_section(menu, NULL, G_MENU_MODEL(section));
    g_object_unref(section);

    GtkWidget *button = gtk_menu_button_new();
    gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(button), "open-menu-symbolic");
    gtk_menu_button_set_primary(GTK_MENU_BUTTON(button), TRUE);  /* F10 */
    gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(button), G_MENU_MODEL(menu));
    gtk_widget_set_tooltip_text(button, _("Main Menu"));
    g_object_unref(menu);
    return button;
}

/* --- Window size ---------------------------------------------------------- */

/* The app's settings, or NULL if the schema is missing: g_settings_new()
 * would abort the program then. Developer builds read the schema from the
 * build tree through a compiled-in path. */
static GSettings *open_settings(void)
{
    GSettingsSchemaSource *source = NULL;
    g_autoptr(GSettingsSchemaSource) own = NULL;
    if (GAUDIT_SCHEMA_DIR[0] != '\0') {
        own = g_settings_schema_source_new_from_directory(GAUDIT_SCHEMA_DIR,
                                                          g_settings_schema_source_get_default(),
                                                          FALSE, NULL);
        source = own;
    } else {
        source = g_settings_schema_source_get_default();
    }
    if (source == NULL)
        return NULL;
    g_autoptr(GSettingsSchema) schema = g_settings_schema_source_lookup(source, GAUDIT_APP_ID, TRUE);
    return schema != NULL ? g_settings_new_full(schema, NULL, NULL) : NULL;
}

static void on_drop_clicked(GtkButton *button, gpointer user_data)
{
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    gtk_menu_button_popdown(GTK_MENU_BUTTON(self->elevated_marker));
    (void)button;
    gaudit_session_drop();
}

static gboolean on_close_request(GtkWindow *window, gpointer user_data)
{
    (void)user_data;
    GauditWindow *self = GAUDIT_WINDOW(window);
    if (self->settings != NULL) {
        int width = 0, height = 0;
        gtk_window_get_default_size(window, &width, &height);
        g_settings_set_boolean(self->settings, "window-maximized", gtk_window_is_maximized(window));
        if (!gtk_window_is_maximized(window) && width > 0 && height > 0) {
            g_settings_set_int(self->settings, "window-width", width);
            g_settings_set_int(self->settings, "window-height", height);
        }
    }
    return FALSE;  /* go on closing */
}

static void restore_size(GauditWindow *self)
{
    int width = 900, height = 600;
    gboolean maximized = FALSE;
    if (self->settings != NULL) {
        width = g_settings_get_int(self->settings, "window-width");
        height = g_settings_get_int(self->settings, "window-height");
        maximized = g_settings_get_boolean(self->settings, "window-maximized");
    }
    gtk_window_set_default_size(GTK_WINDOW(self), width, height);
    if (maximized)
        gtk_window_maximize(GTK_WINDOW(self));
}

static void gaudit_window_dispose(GObject *object)
{
    GauditWindow *win = GAUDIT_WINDOW(object);
    set_weak(&win->home_status, NULL);
    set_weak(&win->elevated_group, NULL);
    g_clear_pointer(&win->elevated_rows, g_ptr_array_unref);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        set_weak(&win->rows[k], NULL);
    g_clear_object(&GAUDIT_WINDOW(object)->settings);
    G_OBJECT_CLASS(gaudit_window_parent_class)->dispose(object);
}

/* --- Construction --------------------------------------------------------- */

static void gaudit_window_class_init(GauditWindowClass *klass)
{
    G_OBJECT_CLASS(klass)->dispose = gaudit_window_dispose;
}

static void gaudit_window_init(GauditWindow *self)
{
    self->pkg = gaudit_pkg_backend_default();
    self->have_status = FALSE;
    self->worst = GAUDIT_VERDICT_UNKNOWN;
    gaudit_probe_init(self->probes);
    self->elevated_rows = g_ptr_array_new();

    /* Translators: Title of the main window and its sidebar. */
    gtk_window_set_title(GTK_WINDOW(self), _("Audit Center"));
    self->settings = open_settings();
    restore_size(self);
    g_signal_connect(self, "close-request", G_CALLBACK(on_close_request), NULL);
    gtk_widget_set_size_request(GTK_WIDGET(self), 360, 294);

    /* Sidebar: Home first, then one row per task. */
    self->sidebar = GTK_LIST_BOX(gtk_list_box_new());
    gtk_widget_add_css_class(GTK_WIDGET(self->sidebar), "navigation-sidebar");
    gtk_list_box_append(self->sidebar,
                        sidebar_row("gaudit-home-symbolic", _("Home"), _("Overall status")));
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks; i++)
        gtk_list_box_append(self->sidebar, sidebar_row(tasks[i].icon, _(tasks[i].title), NULL));
    g_signal_connect(self->sidebar, "row-activated", G_CALLBACK(on_sidebar_row_activated), self);

    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), GTK_WIDGET(self->sidebar));

    /* Sidebar header: no title, primary menu at the end. */
    /* Sidebar header: "Audit Center", with a red disc in front of it while
     * the app holds elevated rights, and the primary menu at the end. */
    AdwHeaderBar *sidebar_header = ADW_HEADER_BAR(adw_header_bar_new());
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    /* The disc is a button: it explains itself and lets the rights go. */
    self->elevated_marker = gtk_menu_button_new();
    gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(self->elevated_marker), "gaudit-elevated-rights-symbolic");
    gtk_widget_add_css_class(self->elevated_marker, "flat");
    gtk_widget_add_css_class(self->elevated_marker, "elevated-marker");
    gtk_widget_set_tooltip_text(self->elevated_marker, _("Running with administrator rights"));
    gtk_accessible_update_property(GTK_ACCESSIBLE(self->elevated_marker),
                                   GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   _("Running with administrator rights"), -1);
    GtkWidget *pop_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(pop_box, 6);
    gtk_widget_set_margin_bottom(pop_box, 6);
    gtk_widget_set_margin_start(pop_box, 6);
    gtk_widget_set_margin_end(pop_box, 6);
    /* The times are the helper's lease (src/helper/lease.h). */
    GtkWidget *pop_text = gtk_label_new(
        _("gAudit holds administrator rights. They end 2 minutes after the last check "
          "that needs them, and at the latest 30 minutes after you gave the password."));
    gtk_label_set_wrap(GTK_LABEL(pop_text), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(pop_text), 36);
    gtk_label_set_xalign(GTK_LABEL(pop_text), 0.0f);
    gtk_box_append(GTK_BOX(pop_box), pop_text);
    GtkWidget *drop = gtk_button_new_with_label(_("Drop Administrator Rights"));
    gtk_widget_add_css_class(drop, "destructive-action");
    g_signal_connect(drop, "clicked", G_CALLBACK(on_drop_clicked), self);
    gtk_box_append(GTK_BOX(pop_box), drop);
    GtkWidget *popover = gtk_popover_new();
    gtk_popover_set_child(GTK_POPOVER(popover), pop_box);
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(self->elevated_marker), popover);
    gtk_widget_set_visible(self->elevated_marker, gaudit_session_elevated());
    gtk_box_append(GTK_BOX(title_box), self->elevated_marker);
    GtkWidget *title = gtk_label_new(_("Audit Center"));
    gtk_widget_add_css_class(title, "title");
    gtk_box_append(GTK_BOX(title_box), title);
    adw_header_bar_set_title_widget(sidebar_header, title_box);
    adw_header_bar_pack_end(sidebar_header, primary_menu_button());

    AdwToolbarView *sidebar_view = ADW_TOOLBAR_VIEW(adw_toolbar_view_new());
    adw_toolbar_view_add_top_bar(sidebar_view, GTK_WIDGET(sidebar_header));
    adw_toolbar_view_set_content(sidebar_view, scroller);
    AdwNavigationPage *sidebar_page =
        adw_navigation_page_new(GTK_WIDGET(sidebar_view), GAUDIT_APP_NAME);
    adw_navigation_page_set_tag(sidebar_page, "sidebar");

    /* Content: a navigation view, so a page 2 can be pushed on top. */
    self->content = ADW_NAVIGATION_VIEW(adw_navigation_view_new());

    self->split = ADW_NAVIGATION_SPLIT_VIEW(adw_navigation_split_view_new());
    adw_navigation_split_view_set_sidebar(self->split, sidebar_page);
    adw_navigation_split_view_set_content(self->split,
        adw_navigation_page_new(GTK_WIDGET(self->content), GAUDIT_APP_NAME));

    GtkWidget *toasts = adw_toast_overlay_new();
    adw_toast_overlay_set_child(ADW_TOAST_OVERLAY(toasts), GTK_WIDGET(self->split));
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(self), toasts);

    /* Narrow windows: the sidebar takes the whole window, and content is
     * shown on its own when selected. */
    AdwBreakpoint *narrow = adw_breakpoint_new(adw_breakpoint_condition_parse("max-width: 500sp"));
    adw_breakpoint_add_setters(narrow, G_OBJECT(self->split), "collapsed", TRUE, NULL);
    adw_application_window_add_breakpoint(ADW_APPLICATION_WINDOW(self), narrow);

    navigate(self, 0, FALSE);
}

void gaudit_window_set_elevated(GauditWindow *self, gboolean elevated)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    if (!elevated)
        gtk_menu_button_popdown(GTK_MENU_BUTTON(self->elevated_marker));
    gtk_widget_set_visible(self->elevated_marker, elevated);
}

GauditWindow *gaudit_window_new(GtkApplication *app)
{
    return g_object_new(GAUDIT_TYPE_WINDOW, "application", app, NULL);
}

void gaudit_window_begin_status(GauditWindow *self)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    gaudit_probe_init(self->probes);
    memset(self->received, 0, sizeof self->received);
    self->have_status = FALSE;
    if (self->home_status != NULL)
        set_summary(self->home_status, FALSE, FALSE, GAUDIT_VERDICT_UNKNOWN);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        fill_row(self, k);
}

void gaudit_window_show_probe(GauditWindow *self, const gaudit_probe_result *result)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    g_return_if_fail(result != NULL && result->kind >= 0 && result->kind < GAUDIT_PROBE_COUNT);
    self->probes[result->kind] = *result;
    self->received[result->kind] = TRUE;
    fill_row(self, result->kind);
}

void gaudit_window_finish_status(GauditWindow *self, gaudit_verdict worst)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    self->have_status = TRUE;
    self->worst = worst;
    if (self->home_status != NULL)
        set_summary(self->home_status, TRUE, strict_passed(self), worst);
}

/* --- Home's checks that need the password ---------------------------------- */

void gaudit_window_elevated_begin(GauditWindow *self)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks && i < GAUDIT_WINDOW_MAX_TASKS; i++)
        if (tasks[i].home_elevated)
            self->elevated[i].state = ELEVATED_RUNNING;
    self->elevated_running = TRUE;
    self->elevated_note = NULL;
    fill_elevated(self);
}

void gaudit_window_elevated_result(GauditWindow *self, gsize task_index, gaudit_run_status status,
                                   const gaudit_firewall_report *result)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    if (task_index >= GAUDIT_WINDOW_MAX_TASKS)
        return;
    if (status == GAUDIT_RUN_OK && result != NULL) {
        self->elevated[task_index].state = ELEVATED_DONE;
        self->elevated[task_index].have = TRUE;
        self->elevated[task_index].fw = *result;
        self->elevated_note = NULL;  /* a fresh result: an old "not checked" no longer applies */
        g_autoptr(GDateTime) now = g_date_time_new_now_local();
        g_autofree char *when = g_date_time_format(now, "%H:%M");
        g_strlcpy(self->elevated_when, when != NULL ? when : "", sizeof self->elevated_when);
    } else {
        /* Nothing new: an earlier result stays, otherwise the row goes;
         * the group's description says why, and how old the rest is. */
        self->elevated[task_index].state =
            self->elevated[task_index].have ? ELEVATED_DONE : ELEVATED_NONE;
        self->elevated_note = status == GAUDIT_RUN_CANCELLED ? _("Not checked: no password was given.")
                            : status == GAUDIT_RUN_DENIED ? _("Not checked: the password was not accepted.")
                            : _("A check could not be completed.");
    }
    fill_elevated(self);
}

void gaudit_window_elevated_busy(GauditWindow *self)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    self->elevated_note = _("Another check is running. Try again when it has finished.");
}

void gaudit_window_elevated_end(GauditWindow *self, gaudit_verdict worst)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    gsize n_tasks;
    gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks && i < GAUDIT_WINDOW_MAX_TASKS; i++)
        if (self->elevated[i].state == ELEVATED_RUNNING)
            self->elevated[i].state = self->elevated[i].have ? ELEVATED_DONE : ELEVATED_NONE;
    self->elevated_running = FALSE;
    fill_elevated(self);
    gaudit_window_set_worst(self, worst);
}

void gaudit_window_set_worst(GauditWindow *self, gaudit_verdict worst)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    /* Before every Home row has its answer, the summary keeps its spinner;
     * finish_status brings in the model's worst then. */
    if (!self->have_status)
        return;
    self->worst = worst;
    if (self->home_status != NULL)
        set_summary(self->home_status, TRUE, strict_passed(self), worst);
}
