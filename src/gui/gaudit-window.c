/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-window.h"
#include "gaudit-crossfade.h"
#include "gaudit-category.h"
#include "gaudit-firewall-text.h"
#include "gaudit-session.h"
#include "gaudit-task.h"
#include "gaudit-task-page.h"
#include "gaudit-run-page.h"
#include "gaudit-report-run.h"
#include "gaudit-report.h"

/* Home's groups: each core plugin's report, its rows in this order. The
 * chevron in a group's title leads to the task named by task_id, when this
 * system has it. Titles are N_()-marked. */
#define HOME_GROUP_MAX_ROWS 8
static const struct {
    const char *title;
    const char *task_id;  /* NULL: no page of its own yet */
    int kinds[HOME_GROUP_MAX_ROWS];
    int n_kinds;
} home_groups[] = {
    /* First: its findings are of immediate use and easy to fix, so the
     * user sees at once what gAudit is good for. */
    { N_("Private Files"), "core.private-files", { 0 }, 0 },
    /* Its report, as one row: the facts are its own collection's. */
    { N_("Updates"), "core.updates", { 0 }, 0 },
    { N_("Flatpak"), NULL, { GAUDIT_PROBE_FLATPAK }, 1 },
    { N_("Snap"), NULL, { GAUDIT_PROBE_SNAP }, 1 },
    /* Listening ports belong here: the firewall check is what turns them
     * into a finding. */
    { N_("Firewall"), "core.firewall", { GAUDIT_PROBE_FIREWALL, GAUDIT_PROBE_LISTENING }, 2 },
    { N_("Antivirus"), NULL, { GAUDIT_PROBE_ANTIVIRUS }, 1 },
};
#define N_HOME_GROUPS (sizeof home_groups / sizeof home_groups[0])

/* Home's report levels, as stored in the "home-level" setting. */
static const char *const home_levels[] = { "quick", "normal", "thorough" };
static const char *const home_level_names[] = { N_("Quick"), N_("Normal"), N_("Thorough") };
#define N_HOME_LEVELS (sizeof home_levels / sizeof home_levels[0])

struct _GauditWindow {
    AdwApplicationWindow parent_instance;

    GSettings *settings;  /* NULL when the schema is not installed */
    /* The user/administrator switch, stuck at the top left beside whatever
     * is the title: in the sidebar's root and each folder, and in the
     * content's pages while the window is narrow (collapsed), so it is
     * always in view. GtkBox each, holding "gaudit-as-user" (a button) and
     * "gaudit-elevated" (a menu button); "gaudit-collapsed-only" on the
     * content's. Weak: a page's goes with it. */
    GPtrArray *switches;
    GtkLabel *folder_title;      /* weak: the open folder's title, which follows the width */
    gboolean attention;          /* a check waits for administrator rights */

    AdwNavigationSplitView *split;
    AdwNavigationView *side_nav;  /* the sidebar: its root, and a plugin's folder on top */
    GtkListBox *sidebar;          /* the root's list: Home and the plugins */
    GtkListBox *folder_list;      /* weak: the open folder's list */
    int folder;                   /* the task whose folder is open, -1 for none */
    gboolean syncing;             /* the two views are being brought in line */
    gboolean close_confirmed;     /* the user chose to stop a heavy run and close */
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
    AdwPreferencesGroup *groups[N_HOME_GROUPS];  /* weak */

    /* Results of tasks run from Home (by task index), kept for the
     * session: the latest result of each run, whoever started it. */
    struct {
        gboolean have;
        gaudit_verdict verdict;
        char *title;
        char when[16];
        gboolean running;
        gboolean waiting;  /* its run waits for administrator rights (the switch) */
        const char *note;  /* static, translated: why the last attempt gave nothing */
        GPtrArray *rows;   /* GauditHomeRow: a plugin's condensate of what fails; NULL for a
                              check that gives one result */
    } results[GAUDIT_WINDOW_MAX_TASKS];
    AdwPreferencesGroup *task_groups[GAUDIT_WINDOW_MAX_TASKS];  /* weak: the task's group */
    GPtrArray *more_rows[GAUDIT_WINDOW_MAX_TASKS];  /* its Home rows after the first (owned) */
    AdwActionRow *check_rows[GAUDIT_WINDOW_MAX_TASKS];  /* weak: rows of tasks on Home */
    AdwActionRow *empty_rows[GAUDIT_WINDOW_MAX_TASKS];  /* weak: "no report at this level" */
    GtkWidget *chevrons[GAUDIT_WINDOW_MAX_TASKS];       /* weak: in the plugins' group titles */
};

G_DEFINE_FINAL_TYPE(GauditWindow, gaudit_window, ADW_TYPE_APPLICATION_WINDOW)

static void navigate(GauditWindow *self, int index, gboolean show_content);

/* --- Home ----------------------------------------------------------------- */

static guint home_level(GauditWindow *self);
static void fill_check_row(GauditWindow *self, gsize i);
static void fill_check_rows(GauditWindow *self);
static void update_report_label(GauditWindow *self);

/* Whether every check that needs the password at the chosen level has run
 * and passed in this session (the status-ok shield); the others count in
 * the summary as findings. At Quick there are none: the shield stays high. */
static gboolean strict_passed(GauditWindow *self)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    guint level = home_level(self);
    gboolean any = FALSE;
    for (gsize i = 0; i < n_tasks && i < GAUDIT_WINDOW_MAX_TASKS; i++) {
        if (!gaudit_task_home_needs_admin(&tasks[i], level))
            continue;
        if (!self->results[i].have || self->results[i].verdict != GAUDIT_VERDICT_OK)
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
    return gaudit_verdict_icon_new(verdict);
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

    case GAUDIT_PROBE_ANTIVIRUS:
        *subtitle = g_strdup(r->verdict == GAUDIT_VERDICT_OK
                             ? _("An antivirus program is installed")
                             : _("No antivirus program found"));
        return _("Antivirus program");

    case GAUDIT_PROBE_FIREWALL:
        *subtitle = g_strdup(r->verdict == GAUDIT_VERDICT_OK
                             ? _("A firewall is installed")
                             : _("No firewall found"));
        return _("Firewall program");

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

/* A task by id, as its index in the task list; -1 when this system has
 * none. */
static int task_by_id(const char *id)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; id != NULL && i < n_tasks; i++)
        if (g_strcmp0(tasks[i].id, id) == 0)
            return (int)i;
    return -1;
}

/* Shows row k as the state is now: a spinner while its answer is on its
 * way, then the result; hidden when the check does not apply here. */
static void fill_row_inner(GauditWindow *self, int k)
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
    g_object_set_data(G_OBJECT(row), "gaudit-capability", NULL);
    g_object_set_data(G_OBJECT(row), "gaudit-category", NULL);
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

/* A group is shown while any of its rows is: one whose checks do not apply
 * here (e.g. Snap without snapd) goes once all of them have said so. */
static void fill_row(GauditWindow *self, int k)
{
    fill_row_inner(self, k);
    for (gsize g = 0; g < N_HOME_GROUPS; g++) {
        gboolean has_k = FALSE, any = FALSE;
        for (int j = 0; j < home_groups[g].n_kinds; j++) {
            int kind = home_groups[g].kinds[j];
            has_k |= kind == k;
            any |= self->rows[kind] != NULL && gtk_widget_get_visible(GTK_WIDGET(self->rows[kind]));
        }
        if (has_k && self->groups[g] != NULL)
            gtk_widget_set_visible(GTK_WIDGET(self->groups[g]), any);
    }
}

/* --- Home: report level and groups ------------------------------------------ */

static void open_plugin(GauditWindow *self, gsize i, int entry);

/* A group's chevron: into the plugin, on the report its Home row is a
 * condensate of, made from the cached collection (whatever level that
 * collection is; the full report takes Run). */
static void on_group_chevron_clicked(GtkButton *button, gpointer user_data)
{
    int index = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "gaudit-index"));
    if (index > 0)
        open_plugin(GAUDIT_WINDOW(user_data), (gsize)index - 1, 1);
}

static void on_level_selected(GObject *row, GParamSpec *pspec, gpointer user_data)
{
    (void)pspec;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    guint i = adw_combo_row_get_selected(ADW_COMBO_ROW(row));
    if (i >= N_HOME_LEVELS || i == home_level(self))
        return;
    if (self->settings != NULL)
        g_settings_set_string(self->settings, "home-level", home_levels[i]);
    fill_check_rows(self);
    gaudit_window_set_worst(self, self->worst);
    /* Picking a level is an explicit act: now its reports are collected,
     * and the password is asked for if they need it. */
    gtk_widget_activate_action(GTK_WIDGET(row), "app.run-level", NULL);
}

/* The level Home runs at; "quick" when unset, unknown or not in the schema. */
static guint home_level(GauditWindow *self)
{
    if (self->settings == NULL)
        return 0;
    g_autoptr(GSettingsSchema) schema = NULL;
    g_object_get(self->settings, "settings-schema", &schema, NULL);
    if (schema == NULL || !g_settings_schema_has_key(schema, "home-level"))
        return 0;
    g_autofree char *level = g_settings_get_string(self->settings, "home-level");
    for (guint i = 0; i < N_HOME_LEVELS; i++)
        if (g_strcmp0(level, home_levels[i]) == 0)
            return i;
    return 0;
}

/* Right below "This computer", always shown: the level is a setting the
 * user's account can change, so Home shows which one it runs at. */
static GtkWidget *build_level(GauditWindow *self)
{
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    GtkStringList *names = gtk_string_list_new(NULL);
    for (gsize i = 0; i < N_HOME_LEVELS; i++)
        gtk_string_list_append(names, _(home_level_names[i]));
    AdwComboRow *row = ADW_COMBO_ROW(adw_combo_row_new());
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), _("Report Level"));
    adw_combo_row_set_model(row, G_LIST_MODEL(names));
    g_object_unref(names);
    adw_combo_row_set_selected(row, home_level(self));
    g_signal_connect(row, "notify::selected", G_CALLBACK(on_level_selected), self);
    adw_preferences_group_add(group, GTK_WIDGET(row));
    return GTK_WIDGET(group);
}

/* A group: a plugin's report on Home. Its probe rows (kinds, may be none),
 * then the plugin's task row; the title's chevron leads to the plugin
 * (task index, -1 for none). A plugin with no probe rows always keeps its
 * group: when nothing of it is shown at the chosen level, a row says so,
 * so no plugin drops out of the list. slot: where to keep the group for
 * hiding it when none of its probes apply (NULL: never hidden). */
static GtkWidget *build_group(GauditWindow *self, const char *title, int task,
                              const int *kinds, int n_kinds, AdwPreferencesGroup **slot)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(group, title);
    if (task >= 0) {
        GtkWidget *chevron = gtk_button_new_from_icon_name("go-next-symbolic");
        gtk_widget_add_css_class(chevron, "flat");
        gtk_widget_set_valign(chevron, GTK_ALIGN_CENTER);
        const char *tip = _(tasks[task].home_tooltip != NULL ? tasks[task].home_tooltip
                                                             : tasks[task].title);
        gtk_widget_set_tooltip_text(chevron, tip);
        gtk_accessible_update_property(GTK_ACCESSIBLE(chevron), GTK_ACCESSIBLE_PROPERTY_LABEL, tip, -1);
        g_object_set_data(G_OBJECT(chevron), "gaudit-index", GINT_TO_POINTER(task + 1));
        g_signal_connect(chevron, "clicked", G_CALLBACK(on_group_chevron_clicked), self);
        adw_preferences_group_set_header_suffix(group, chevron);
        /* Always there: with nothing cached yet, the report page follows the
         * run under way or starts one. */
        if (task < GAUDIT_WINDOW_MAX_TASKS)
            set_weak(&self->chevrons[task], chevron);
    }
    if (slot != NULL)
        set_weak(slot, group);
    for (int j = 0; j < n_kinds; j++) {
        int k = kinds[j];
        AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
        /* Subtitles carry data from the system: never interpret markup. */
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        g_signal_connect(row, "activated", G_CALLBACK(on_missing_row_activated), self);
        set_weak(&self->rows[k], row);
        adw_preferences_group_add(group, GTK_WIDGET(row));
        fill_row(self, k);
    }
    if (task < 0 || task >= GAUDIT_WINDOW_MAX_TASKS)
        return GTK_WIDGET(group);
    const GauditTaskInfo *info = &tasks[task];
    /* The plugin's task, at the levels that include it. */
    AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row),
                                  _(info->home_title != NULL ? info->home_title : info->title));
    /* The prefix holds the task's icon, a spinner or the verdict. */
    GtkWidget *prefix = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    g_object_set_data(G_OBJECT(row), "gaudit-prefix", prefix);
    adw_action_row_add_prefix(row, prefix);
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_preferences_group_add(group, GTK_WIDGET(row));
    set_weak(&self->check_rows[task], row);
    set_weak(&self->task_groups[task], group);
    if (n_kinds == 0) {
        AdwActionRow *empty = ADW_ACTION_ROW(adw_action_row_new());
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(empty), _("No report at this level"));
        adw_action_row_add_prefix(empty, gtk_image_new_from_icon_name(info->icon));
        adw_preferences_group_add(group, GTK_WIDGET(empty));
        set_weak(&self->empty_rows[task], empty);
    }
    fill_check_row(self, (gsize)task);
    return GTK_WIDGET(group);
}

/* Whether a core group stands for task i. */
static gboolean task_has_core_group(gsize i)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize g = 0; g < N_HOME_GROUPS; g++)
        if (g_strcmp0(home_groups[g].task_id, tasks[i].id) == 0)
            return TRUE;
    return FALSE;
}

/* --- Home: tasks run at the chosen level ----------------------------------- */

/* A task's row on Home: its state, or once it has run in this session, the
 * verdict and what was found, with the time. In its group it is shown at
 * the levels that include it, and always once it has a result: results do
 * not vanish when the level goes down. */
/* Home's rows after the first, as the last report gave them. */
static void clear_more_rows(GauditWindow *self, gsize i)
{
    if (self->more_rows[i] == NULL)
        return;
    for (guint r = 0; r < self->more_rows[i]->len; r++) {
        GtkWidget *w = g_ptr_array_index(self->more_rows[i], r);
        if (self->task_groups[i] != NULL && gtk_widget_get_parent(w) != NULL)
            adw_preferences_group_remove(self->task_groups[i], w);
    }
    g_clear_pointer(&self->more_rows[i], g_ptr_array_unref);
}

static AdwActionRow *home_row_new(const GauditHomeRow *h)
{
    AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
    /* The rule's texts, filled in with data from the system: plain text. */
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), h->title);
    adw_action_row_set_subtitle(row, h->subtitle);
    adw_action_row_add_prefix(row, verdict_icon(h->verdict));
    return row;
}

static void fill_check_row_inner(GauditWindow *self, gsize i)
{
    AdwActionRow *row = self->check_rows[i];
    if (row == NULL)
        return;
    clear_more_rows(self, i);
    if (self->task_groups[i] != NULL)
        adw_preferences_group_set_description(self->task_groups[i], NULL);
    GtkWidget *prefix = g_object_get_data(G_OBJECT(row), "gaudit-prefix");
    GtkWidget *old = gtk_widget_get_first_child(prefix);
    if (old != NULL)
        gtk_box_remove(GTK_BOX(prefix), old);

    gsize n_tasks;
    const GauditTaskInfo *task = &gaudit_tasks_get(&n_tasks)[i];
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row),
                                  _(task->home_title != NULL ? task->home_title : task->title));
    /* Shown at the levels that include it (none for a task with no Home
     * report), and always once it has a result. */
    gboolean shown = gaudit_task_home_command(task, home_level(self)) != NULL
                     || self->results[i].have || self->results[i].running;
    gtk_widget_set_visible(GTK_WIDGET(row), shown);
    AdwActionRow *empty = self->empty_rows[i];
    if (empty != NULL) {
        gtk_widget_set_visible(GTK_WIDGET(empty), !shown);
        guint from_level = gaudit_task_home_from(task);
        if (from_level < GAUDIT_LEVEL_COUNT) {
            /* Translators: the level a plugin's report on Home first shows
             * at, e.g. "Shown from Thorough". */
            g_autofree char *from = g_strdup_printf(_("Shown from %s"),
                                                    _(home_level_names[from_level]));
            adw_action_row_set_subtitle(empty, from);
        } else {
            adw_action_row_set_subtitle(empty, _("Its check runs on the plugin's own page"));
        }
    }
    if (self->results[i].running && self->results[i].waiting) {
        /* Something must be done: switch to administrator. */
        gtk_box_append(GTK_BOX(prefix), gtk_image_new_from_icon_name("gaudit-questionmark-symbolic"));
        adw_action_row_set_subtitle(row, _("Switch to administrator to run this check"));
        return;
    }
    if (self->results[i].running) {
        gtk_box_append(GTK_BOX(prefix), row_spinner());
        adw_action_row_set_subtitle(row, _("Checking…"));
        return;
    }
    if (self->results[i].have && self->results[i].rows != NULL && self->results[i].rows->len > 0) {
        /* A plugin's condensate: one row per problem, each a summary, or
         * one saying all is well; the time it was checked under the title. */
        GPtrArray *rows = self->results[i].rows;
        const GauditHomeRow *first = g_ptr_array_index(rows, 0);
        gtk_box_append(GTK_BOX(prefix), verdict_icon(first->verdict));
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), first->title);
        adw_action_row_set_subtitle(row, first->subtitle);
        self->more_rows[i] = g_ptr_array_new_with_free_func(g_object_unref);
        for (guint r = 1; r < rows->len && self->task_groups[i] != NULL; r++) {
            AdwActionRow *more = home_row_new(g_ptr_array_index(rows, r));
            g_ptr_array_add(self->more_rows[i], g_object_ref(more));
            adw_preferences_group_add(self->task_groups[i], GTK_WIDGET(more));
            gtk_widget_set_visible(GTK_WIDGET(more), shown);
        }
        if (self->task_groups[i] != NULL) {
            /* Translators: under a plugin's group on Home, e.g. "Checked at 14:32". */
            g_autofree char *at = g_strdup_printf(_("Checked at %s"), self->results[i].when);
            adw_preferences_group_set_description(self->task_groups[i], at);
        }
        return;
    }
    if (self->results[i].have) {
        gtk_box_append(GTK_BOX(prefix), verdict_icon(self->results[i].verdict));
        /* Translators: "<what was found> · checked at <time>", e.g.
         * "No changed package files found · checked at 14:32". */
        g_autofree char *subtitle = g_strdup_printf(_("%s · checked at %s"),
                                                    self->results[i].title, self->results[i].when);
        adw_action_row_set_subtitle(row, subtitle);
        return;
    }
    g_autoptr(GPtrArray) missing = gaudit_task_missing_packages(task, self->pkg);
    gboolean waits_for_admin = missing != NULL && missing->len == 0 && self->results[i].note == NULL
                               && gaudit_task_home_needs_admin(task, home_level(self))
                               && !gaudit_session_elevated();
    /* A row that needs the user to switch to administrator gets a question
     * mark: something must be done. Otherwise the plugin's own icon. */
    gtk_box_append(GTK_BOX(prefix), gtk_image_new_from_icon_name(
        waits_for_admin ? "gaudit-questionmark-symbolic" : task->icon));
    adw_action_row_set_subtitle(row, missing == NULL ? _("Not available on this system")
                                   : missing->len > 0 ? _("Software is missing")
                                   : self->results[i].note != NULL ? self->results[i].note
                                   : waits_for_admin ? _("Switch to administrator to run this check")
                                   : _("Not run yet"));
}

static void fill_check_row(GauditWindow *self, gsize i)
{
    fill_check_row_inner(self, i);
}

static void fill_check_rows(GauditWindow *self)
{
    for (gsize i = 0; i < GAUDIT_WINDOW_MAX_TASKS; i++)
        fill_check_row(self, i);
}

static GPtrArray *copy_home_rows(GPtrArray *rows)
{
    if (rows == NULL)
        return NULL;
    GPtrArray *copy = g_ptr_array_new_with_free_func(g_free);
    for (guint r = 0; r < rows->len; r++) {
        const GauditHomeRow *h = g_ptr_array_index(rows, r);
        /* One block: the struct, then its two strings. */
        gsize lt = strlen(h->title) + 1, ls = strlen(h->subtitle != NULL ? h->subtitle : "") + 1;
        GauditHomeRow *c = g_malloc(sizeof *c + lt + ls);
        c->verdict = h->verdict;
        c->title = (char *)(c + 1);
        c->subtitle = c->title + lt;
        memcpy(c->title, h->title, lt);
        memcpy(c->subtitle, h->subtitle != NULL ? h->subtitle : "", ls);
        g_ptr_array_add(copy, c);
    }
    return copy;
}

void gaudit_window_task_report(GauditWindow *self, gsize task_index, gaudit_verdict verdict,
                               const char *title, GPtrArray *rows)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self) && title != NULL);
    if (task_index >= GAUDIT_WINDOW_MAX_TASKS)
        return;
    self->results[task_index].have = TRUE;
    self->results[task_index].running = FALSE;
    self->results[task_index].waiting = FALSE;
    self->results[task_index].note = NULL;
    self->results[task_index].verdict = verdict;
    g_free(self->results[task_index].title);
    self->results[task_index].title = g_strdup(title);
    g_clear_pointer(&self->results[task_index].rows, g_ptr_array_unref);
    self->results[task_index].rows = copy_home_rows(rows);
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *when = g_date_time_format(now, "%H:%M");
    g_strlcpy(self->results[task_index].when, when != NULL ? when : "",
              sizeof self->results[task_index].when);
    fill_check_row(self, task_index);
    update_report_label(self);  /* a new collection may have come with it */
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

        gtk_box_append(GTK_BOX(box), build_level(self));
        for (gsize g = 0; g < N_HOME_GROUPS; g++)
            gtk_box_append(GTK_BOX(box),
                           build_group(self, _(home_groups[g].title), task_by_id(home_groups[g].task_id),
                                       home_groups[g].kinds, home_groups[g].n_kinds, &self->groups[g]));
    }


    /* Every other plugin gets a group of its own. */
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks; i++)
        if (!task_has_core_group(i))
            gtk_box_append(GTK_BOX(box), build_group(self, _(tasks[i].title), (int)i, NULL, 0, NULL));

    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(status, clamp);

    return gaudit_page_wrap(GTK_WIDGET(status), _("Home"), "home");
}

/* --- Navigation ----------------------------------------------------------- */

/* Inside a plugin, the content's title says where: "<plugin> › <page>"
 * (e.g. "Private Files › Parameters"); each page's own title is the second
 * part. Done once per page. */
static void title_in_folder(GauditWindow *self, AdwNavigationPage *page)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (page == NULL || self->folder < 0 || (gsize)self->folder >= n_tasks
        || g_object_get_data(G_OBJECT(page), "gaudit-titled") != NULL)
        return;
    /* Translators: the content's title inside a plugin, "<plugin> › <page>",
     * e.g. "Private Files › Parameters". Turn the separator around for
     * right-to-left languages if it reads wrong. */
    g_autofree char *title = g_strdup_printf(_("%s › %s"), _(tasks[self->folder].title),
                                             adw_navigation_page_get_title(page));
    adw_navigation_page_set_title(page, title);
    g_object_set_data(G_OBJECT(page), "gaudit-titled", GINT_TO_POINTER(1));
}

/* --- The content's header bar: Reload and the page's context menu ----------
 *
 * At the end of the header bar: the context menu for the page shown (often
 * the same for all of a plugin's pages), and Reload beside it, which starts
 * the page's current process again: Home's checks on Home, the collection
 * behind a report (with the same parameters) on a report or a run. Pages
 * without a process (Parameters, a fix) have no Reload. */

static void open_entry(GauditWindow *self, int entry);
static void go_home(GauditWindow *self, gboolean show);
static void content_set(GauditWindow *self, AdwNavigationPage *page);

static void on_reload_clicked(GtkButton *button, gpointer user_data)
{
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    AdwNavigationPage *page = g_object_get_data(G_OBJECT(button), "gaudit-page");
    const char *tag = page != NULL ? adw_navigation_page_get_tag(page) : NULL;
    if (g_strcmp0(tag, "home") == 0) {
        gtk_widget_activate_action(GTK_WIDGET(button), "app.reload-home", NULL);
        return;
    }
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (self->folder < 0 || (gsize)self->folder >= n_tasks)
        return;
    if (g_strcmp0(tag, tasks[self->folder].id) == 0) {
        /* On Parameters, its process is making the parameters: back to the
         * defaults, the generated ones made again, and the page with them. */
        gaudit_task_reset_parameters(&tasks[self->folder]);
        open_entry(self, 0);
        GtkWidget *overlay = gtk_widget_get_ancestor(GTK_WIDGET(self->content), ADW_TYPE_TOAST_OVERLAY);
        if (overlay != NULL)
            adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(overlay),
                                        adw_toast_new(_("The parameters are set back")));
        return;
    }
    AdwNavigationPage *again = gaudit_run_page_again(&tasks[self->folder]);
    title_in_folder(self, again);
    content_set(self, again);
}

/* Home's information page, on top of Home: back leads to Home. */
static void on_home_info(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    (void)action;
    (void)param;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    AdwNavigationPage *page = gaudit_home_info_page_new();
    /* Translators: the content's title, "<page> › <page>", here "Home › Information". */
    g_autofree char *title = g_strdup_printf(_("%s › %s"), _("Home"), _("Information"));
    adw_navigation_page_set_title(page, title);
    adw_navigation_view_push(self->content, page);
    gtk_list_box_unselect_all(self->sidebar);  /* none of the sidebar's entries */
}

/* The plugin's About dialog. */
static void on_about_plugin(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    (void)action;
    (void)param;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (self->folder >= 0 && (gsize)self->folder < n_tasks)
        gaudit_plugin_about_dialog(&tasks[self->folder], GTK_WIDGET(self));
}

/* Page 0, on top of the page shown: back leads to where the user was. */
static void on_plugin_info(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    (void)action;
    (void)param;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (self->folder >= 0 && (gsize)self->folder < n_tasks) {
        /* What it was opened from: Parameters, or a report (simplified or full). */
        const GauditTaskInfo *task = &tasks[self->folder];
        AdwNavigationPage *shown = adw_navigation_view_get_visible_page(self->content);
        const char *tag = shown != NULL ? adw_navigation_page_get_tag(shown) : NULL;
        GauditInfoFrom from = GAUDIT_INFO_PLAIN;
        if (g_strcmp0(tag, task->id) == 0)
            from = GAUDIT_INFO_PARAMETERS;
        else if (g_strcmp0(tag, "report") == 0 || g_strcmp0(tag, "run") == 0)
            from = gaudit_cache_lines(task, NULL) != NULL && !gaudit_cache_full(task)
                   ? GAUDIT_INFO_SIMPLIFIED : GAUDIT_INFO_REPORT;
        adw_navigation_view_push(self->content, gaudit_plugin_about_page_new(task, from));
        /* Page 0 is none of the folder's entries: nothing marked. */
        if (self->folder_list != NULL)
            gtk_list_box_unselect_all(self->folder_list);
    }
}

static GtkWidget *switch_new(GauditWindow *self, gboolean collapsed_only);
static GtkWidget *titled(GtkWidget *switch_box, const char *text, GtkLabel **label_out);
static void update_folder_title(GauditWindow *self);

static void decorate(GauditWindow *self, AdwNavigationPage *page)
{
    AdwHeaderBar *header = page != NULL ? g_object_get_data(G_OBJECT(page), "gaudit-header") : NULL;
    if (header == NULL || g_object_get_data(G_OBJECT(page), "gaudit-decorated") != NULL)
        return;
    g_object_set_data(G_OBJECT(page), "gaudit-decorated", GINT_TO_POINTER(1));
    /* The page's title with the switch to its left, shown while the window
     * is narrow and the sidebar, with its own, is out of view. */
    GtkLabel *title = NULL;
    adw_header_bar_set_title_widget(header, titled(switch_new(self, TRUE), "", &title));
    g_object_bind_property(page, "title", title, "label", G_BINDING_SYNC_CREATE);
    const char *tag = adw_navigation_page_get_tag(page);
    gboolean home = g_strcmp0(tag, "home") == 0;
    gboolean in_plugin = !home && self->folder >= 0;
    /* At the end: first packed is outermost, so the menu, then Reload. */
    if (home) {
        /* Home's menu: its information page and About gAudit, as a
         * plugin's has its information and its About (no plugin entries). */
        GMenu *menu = g_menu_new();
        g_menu_append(menu, _("Information"), "win.home-info");
        /* Translators: %s is the application name, which is not translated. */
        g_autofree char *about = g_strdup_printf(_("About %s"), GAUDIT_APP_NAME);
        g_menu_append(menu, about, "app.about");
        GtkWidget *button = gtk_menu_button_new();
        gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(button), "gaudit-context-menu-symbolic");
        gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(button), G_MENU_MODEL(menu));
        gtk_widget_set_tooltip_text(button, _("Menu for this page"));
        gtk_accessible_update_property(GTK_ACCESSIBLE(button), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                       _("Menu for this page"), -1);
        g_object_unref(menu);
        adw_header_bar_pack_end(header, button);
    }
    if (in_plugin) {
        GMenu *menu = g_menu_new();
        gsize n_tasks;
        const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
        /* Kept simple: the pages are in the sidebar already. */
        g_autofree char *label = g_strdup_printf(_("About %s"), _(tasks[self->folder].title));
        g_menu_append(menu, _("Information"), "win.plugin-info");
        g_menu_append(menu, label, "win.about-plugin");
        GtkWidget *button = gtk_menu_button_new();
        gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(button), "gaudit-context-menu-symbolic");
        gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(button), G_MENU_MODEL(menu));
        gtk_widget_set_tooltip_text(button, _("Menu for this page"));
        gtk_accessible_update_property(GTK_ACCESSIBLE(button), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                       _("Menu for this page"), -1);
        g_object_unref(menu);
        adw_header_bar_pack_end(header, button);
    }
    gsize n_tasks;
    const GauditTaskInfo *all = gaudit_tasks_get(&n_tasks);
    gboolean params = in_plugin && (gsize)self->folder < n_tasks
                      && g_strcmp0(tag, all[self->folder].id) == 0
                      && (all[self->folder].param_folders || all[self->folder].param_read_limit
                          || all[self->folder].param_caches);
    if (home || params || g_strcmp0(tag, "report") == 0 || g_strcmp0(tag, "run") == 0) {
        const char *tip = home ? _("Check again")
                        : params ? _("Set the parameters back")
                        : _("Collect again with the same settings");
        GtkWidget *reload = gtk_button_new_from_icon_name("gaudit-reload-symbolic");
        gtk_widget_set_tooltip_text(reload, tip);
        gtk_accessible_update_property(GTK_ACCESSIBLE(reload), GTK_ACCESSIBLE_PROPERTY_LABEL, tip, -1);
        g_object_set_data(G_OBJECT(reload), "gaudit-page", page);
        g_signal_connect(reload, "clicked", G_CALLBACK(on_reload_clicked), self);
        adw_header_bar_pack_end(header, reload);
    }
}

/* Pages pushed inside a plugin (a run, a fix) get the plugin in their title. */
static void on_content_pushed(AdwNavigationView *nav, gpointer user_data)
{
    AdwNavigationPage *page = adw_navigation_view_get_visible_page(nav);
    title_in_folder(GAUDIT_WINDOW(user_data), page);
    decorate(GAUDIT_WINDOW(user_data), page);
}

/* The content: one page that has an entry in the sidebar (page; NULL for
 * Home), alone at the bottom, so it has no back button: the user moves
 * between such pages with the sidebar, which marks where they are. Pages
 * without an entry (a fix, information) are pushed on top of it and so
 * get a back button, a clear way back (John, 2026-11-15). */
static void content_set(GauditWindow *self, AdwNavigationPage *page)
{
    AdwNavigationPage *root = page != NULL ? page : build_home(self);
    decorate(self, root);
    self->syncing = TRUE;
    adw_navigation_view_replace(self->content, &root, 1);
    self->syncing = FALSE;
}

static void show_content(GauditWindow *self)
{
    adw_navigation_split_view_set_show_content(self->split, TRUE);
}

static void select_root(GauditWindow *self, int index)
{
    GtkListBoxRow *row = gtk_list_box_get_row_at_index(self->sidebar, index);
    if (row != NULL && gtk_list_box_get_selected_row(self->sidebar) != row)
        gtk_list_box_select_row(self->sidebar, row);
}

/* Back to Home, from anywhere: the sidebar to its root, the content to Home. */
static void go_home(GauditWindow *self, gboolean show)
{
    self->syncing = TRUE;
    adw_navigation_view_pop_to_tag(self->side_nav, "sidebar");
    self->syncing = FALSE;
    self->folder = -1;
    content_set(self, NULL);
    select_root(self, 0);
    if (show)
        show_content(self);
}

static void select_folder_row(GauditWindow *self, int index)
{
    GtkListBoxRow *row = self->folder_list != NULL
        ? gtk_list_box_get_row_at_index(self->folder_list, index) : NULL;
    if (row != NULL && gtk_list_box_get_selected_row(self->folder_list) != row)
        gtk_list_box_select_row(self->folder_list, row);
}

/* A folder entry: 0 the plugin's parameters (page 1), 1 its report, from
 * the cached collection; with nothing cached, a run is started (from page
 * 1 when the plugin takes parameters). */
static void open_entry(GauditWindow *self, int entry)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (self->folder < 0 || (gsize)self->folder >= n_tasks)
        return;
    const GauditTaskInfo *task = &tasks[self->folder];
    AdwNavigationPage *page = NULL;
    if (entry == 1) {
        page = gaudit_cached_report_page_new(task);
        /* Nothing cached yet, but its run is under way (e.g. Home's at
         * start-up): follow that one, rather than start another. */
        if (page == NULL)
            page = gaudit_run_page_follow(task);
        if (page == NULL && task->n_params == 0) {
            g_autoptr(GPtrArray) missing = gaudit_task_missing_packages(task, self->pkg);
            if (missing != NULL && missing->len == 0)
                page = gaudit_run_page_new(task);
        }
        if (page == NULL)
            entry = 0;  /* to page 1, to run it from there */
    }
    if (page == NULL) {
        page = gaudit_task_page_new(task, self->pkg);
        adw_navigation_page_set_title(page, _("Parameters"));
    }
    title_in_folder(self, page);
    content_set(self, page);
    select_folder_row(self, entry);
    show_content(self);
}

static void on_folder_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer user_data)
{
    (void)box;
    open_entry(GAUDIT_WINDOW(user_data), gtk_list_box_row_get_index(row));
}

static GtkWidget *sidebar_row(const char *icon, const char *title, const char *subtitle);
static GtkWidget *primary_menu_button(void);

/* What the folder's report entry holds: the report after Run on
 * Parameters, the simplified one Home made, or (nothing cached) a run of
 * the report. */
static const char *report_label(const GauditTaskInfo *task)
{
    return gaudit_cache_lines(task, NULL) == NULL || gaudit_cache_full(task)
           ? _("Report") : _("Simplified Report");
}

/* The open folder's report entry follows the cache. */
static void update_report_label(GauditWindow *self)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    GtkListBoxRow *row = self->folder_list != NULL
        ? gtk_list_box_get_row_at_index(self->folder_list, 1) : NULL;
    if (row == NULL || self->folder < 0 || (gsize)self->folder >= n_tasks)
        return;
    GtkLabel *label = g_object_get_data(G_OBJECT(row), "gaudit-title");
    if (label != NULL)
        gtk_label_set_text(label, report_label(&tasks[self->folder]));
}

/* The plugin's folder in the sidebar: its parameters first, then its
 * reports (for now one, until the plugin gives the list itself). No title
 * and no administrator switch, a back button; the primary menu stays. */
static AdwNavigationPage *folder_page(GauditWindow *self, const GauditTaskInfo *task)
{
    GtkListBox *list = GTK_LIST_BOX(gtk_list_box_new());
    gtk_widget_add_css_class(GTK_WIDGET(list), "navigation-sidebar");
    gtk_list_box_append(list, sidebar_row("preferences-system-symbolic", _("Parameters"), NULL));
    gtk_list_box_append(list, sidebar_row("gaudit-documents-symbolic", report_label(task), NULL));
    g_signal_connect(list, "row-activated", G_CALLBACK(on_folder_row_activated), self);
    set_weak(&self->folder_list, list);

    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), GTK_WIDGET(list));
    AdwHeaderBar *header = ADW_HEADER_BAR(adw_header_bar_new());
    /* The switch and a title, also beside the back button: "Audit Center"
     * while the content shows beside it (its title names the plugin), the
     * plugin's name when the window is narrow and the folder shows alone. */
    GtkLabel *folder_title = NULL;
    adw_header_bar_set_title_widget(header, titled(switch_new(self, FALSE), "", &folder_title));
    set_weak(&self->folder_title, folder_title);
    g_object_set_data_full(G_OBJECT(folder_title), "gaudit-plugin", g_strdup(_(task->title)), g_free);
    update_folder_title(self);
    adw_header_bar_pack_end(header, primary_menu_button());
    AdwToolbarView *view = ADW_TOOLBAR_VIEW(adw_toolbar_view_new());
    adw_toolbar_view_add_top_bar(view, GTK_WIDGET(header));
    adw_toolbar_view_set_content(view, scroller);
    g_autofree char *tag = g_strdup_printf("folder-%s", task->id);
    AdwNavigationPage *page = adw_navigation_page_new(GTK_WIDGET(view), _(task->title));
    adw_navigation_page_set_tag(page, tag);
    return page;
}

/* Into a plugin: its folder slides in, and the content shows entry (0
 * page 1, 1 the report from the cache; -1: page 1, or in a narrow window
 * only the folder, until an entry is picked). */
static void open_plugin(GauditWindow *self, gsize i, int entry)
{
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    g_return_if_fail(i < n_tasks);
    if (self->folder != (int)i) {
        self->syncing = TRUE;
        adw_navigation_view_pop_to_tag(self->side_nav, "sidebar");
        adw_navigation_view_push(self->side_nav, folder_page(self, &tasks[i]));
        self->syncing = FALSE;
        self->folder = (int)i;
    }
    select_root(self, (int)i + 1);
    if (entry < 0 && adw_navigation_split_view_get_collapsed(self->split)) {
        if (self->folder_list != NULL)
            gtk_list_box_unselect_all(self->folder_list);
        return;
    }
    open_entry(self, entry < 0 ? 0 : entry);
}

/* index 0 is Home, index i > 0 is task i - 1. */
static void navigate(GauditWindow *self, int index, gboolean show)
{
    gsize n_tasks;
    gaudit_tasks_get(&n_tasks);
    g_return_if_fail(index >= 0 && (gsize)index <= n_tasks);
    if (index == 0)
        go_home(self, show);
    else
        open_plugin(self, (gsize)index - 1, -1);
}

static void on_sidebar_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer user_data)
{
    (void)box;
    navigate(GAUDIT_WINDOW(user_data), gtk_list_box_row_get_index(row), TRUE);
}

/* The folder's back button: back to Home in the content too. */
static void on_side_popped(AdwNavigationView *nav, AdwNavigationPage *page, gpointer user_data)
{
    (void)nav;
    (void)page;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    if (self->syncing)
        return;
    self->folder = -1;
    content_set(self, NULL);
    select_root(self, 0);
}

/* The content's back button to Home: the folder closes too. A fix page
 * popped back to its report leaves the folder open. */
static void on_content_popped(AdwNavigationView *nav, AdwNavigationPage *page, gpointer user_data)
{
    (void)page;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    AdwNavigationPage *visible = adw_navigation_view_get_visible_page(nav);
    if (self->syncing || visible == NULL)
        return;
    /* Back from a page without a sidebar entry: the entry of the page now
     * shown is marked again. The content never goes back past the page
     * the sidebar chose, so the folder stays as it is. */
    const char *tag = adw_navigation_page_get_tag(visible);
    if (self->folder < 0) {
        if (g_strcmp0(tag, "home") == 0)
            select_root(self, 0);
        return;
    }
    if (g_strcmp0(tag, "report") == 0 || g_strcmp0(tag, "run") == 0)
        select_folder_row(self, 1);
    else if (g_strcmp0(tag, "about") != 0 && g_strcmp0(tag, "fix") != 0)
        select_folder_row(self, 0);
}

/* Run on Parameters: the report is a page with its own sidebar entry, so
 * the content changes to it (no back button) and the entry is marked. */
static void on_start(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    (void)action;
    (void)param;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (self->folder < 0 || (gsize)self->folder >= n_tasks)
        return;
    AdwNavigationPage *page = gaudit_run_page_new(&tasks[self->folder]);
    title_in_folder(self, page);
    content_set(self, page);
    select_folder_row(self, 1);
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
    g_object_set_data(G_OBJECT(row), "gaudit-title", label);
    return row;
}

static GtkWidget *primary_menu_button(void)
{
    GMenu *section = g_menu_new();
    g_menu_append(section, _("_Preferences"), "app.preferences");
    g_menu_append(section, _("_Keyboard Shortcuts"), "app.shortcuts");
    /* About gAudit is in Home's context menu, beside Home's information. */

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
    (void)user_data;
    GtkWidget *popover = gtk_widget_get_ancestor(GTK_WIDGET(button), GTK_TYPE_POPOVER);
    if (popover != NULL)
        gtk_popover_popdown(GTK_POPOVER(popover));
    gaudit_session_drop();
}

/* One switch as the state is now. */
static void switch_update(GauditWindow *self, GtkWidget *box)
{
    gboolean elevated = gaudit_session_elevated();
    GtkWidget *as_user = g_object_get_data(G_OBJECT(box), "gaudit-as-user");
    GtkWidget *marker = g_object_get_data(G_OBJECT(box), "gaudit-elevated");
    if (!elevated)
        gtk_menu_button_popdown(GTK_MENU_BUTTON(marker));
    gtk_widget_set_visible(marker, elevated);
    gtk_widget_set_visible(as_user, !elevated);
    /* The content's own only while the sidebar is out of view. */
    gboolean collapsed = self->split != NULL && adw_navigation_split_view_get_collapsed(self->split);
    gtk_widget_set_visible(box, g_object_get_data(G_OBJECT(box), "gaudit-collapsed-only") == NULL
                                || collapsed);
    /* A disc in the accent colour behind it while a check waits for the
     * rights: not an error, it shows where the switch is. */
    if (self->attention)
        gtk_widget_add_css_class(as_user, "gaudit-attention");
    else
        gtk_widget_remove_css_class(as_user, "gaudit-attention");
}

static void switch_gone(gpointer data, GObject *box)
{
    GauditWindow *self = data;
    if (self->switches != NULL)
        g_ptr_array_remove(self->switches, box);
}

/* The switch: as the user a button (one click asks for the password, or
 * lets checks waiting for it go on), with administrator rights a menu
 * button that explains the lease and lets the rights go. The two icons
 * differ in shape (one person, two), not in colour only. */
static GtkWidget *switch_new(GauditWindow *self, gboolean collapsed_only)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    if (collapsed_only)
        g_object_set_data(G_OBJECT(box), "gaudit-collapsed-only", GINT_TO_POINTER(1));
    GtkWidget *as_user = gtk_button_new_from_icon_name("gaudit-user-symbolic");
    gtk_actionable_set_action_name(GTK_ACTIONABLE(as_user), "app.elevate");
    gtk_widget_set_tooltip_text(as_user, _("Running as you. Switch to administrator"));
    gtk_accessible_update_property(GTK_ACCESSIBLE(as_user), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   _("Running as you. Switch to administrator"), -1);
    gtk_box_append(GTK_BOX(box), as_user);

    GtkWidget *marker = gtk_menu_button_new();
    gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(marker), "gaudit-superuser-symbolic");
    gtk_widget_set_tooltip_text(marker, _("Running with administrator rights"));
    gtk_accessible_update_property(GTK_ACCESSIBLE(marker), GTK_ACCESSIBLE_PROPERTY_LABEL,
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
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(marker), popover);
    gtk_box_append(GTK_BOX(box), marker);

    g_object_set_data(G_OBJECT(box), "gaudit-as-user", as_user);
    g_object_set_data(G_OBJECT(box), "gaudit-elevated", marker);
    if (self->switches == NULL)
        self->switches = g_ptr_array_new();
    g_ptr_array_add(self->switches, box);
    g_object_weak_ref(G_OBJECT(box), switch_gone, self);
    switch_update(self, box);
    return box;
}

static void switches_update(GauditWindow *self)
{
    for (guint i = 0; self->switches != NULL && i < self->switches->len; i++)
        switch_update(self, g_ptr_array_index(self->switches, i));
}

/* A header's title with the switch to its left. label_out (may be NULL)
 * gets the label, for a title that changes. */
static GtkWidget *titled(GtkWidget *switch_box, const char *text, GtkLabel **label_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(box), switch_box);
    GtkWidget *label = gtk_label_new(text);
    gtk_widget_add_css_class(label, "title");
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_label_set_single_line_mode(GTK_LABEL(label), TRUE);
    gtk_box_append(GTK_BOX(box), label);
    if (label_out != NULL)
        *label_out = GTK_LABEL(label);
    return box;
}

static void update_folder_title(GauditWindow *self)
{
    if (self->folder_title == NULL)
        return;
    gboolean collapsed = self->split != NULL && adw_navigation_split_view_get_collapsed(self->split);
    const char *plugin = g_object_get_data(G_OBJECT(self->folder_title), "gaudit-plugin");
    gtk_label_set_text(self->folder_title, collapsed && plugin != NULL ? plugin : _("Audit Center"));
}

static void on_collapsed(GObject *split, GParamSpec *pspec, gpointer user_data)
{
    (void)split;
    (void)pspec;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    switches_update(self);
    update_folder_title(self);
}

static void on_close_answer(AdwAlertDialog *dialog, const char *response, gpointer user_data)
{
    (void)dialog;
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    if (g_strcmp0(response, "stop") != 0)
        return;
    self->close_confirmed = TRUE;
    gaudit_session_cancel();
    gtk_window_close(GTK_WINDOW(self));
}

static gboolean on_close_request(GtkWindow *window, gpointer user_data)
{
    (void)user_data;
    GauditWindow *self = GAUDIT_WINDOW(window);
    /* A heavy run under way, in the last window: ask first. Otherwise the
     * window closes, and with the last one the app ends. */
    GtkApplication *app = gtk_window_get_application(window);
    gboolean last = app == NULL || g_list_length(gtk_application_get_windows(app)) <= 1;
    if (!self->close_confirmed && last && gaudit_session_running_long()) {
        AdwDialog *dialog = adw_alert_dialog_new(_("Stop the Check and Close?"),
            _("A check is still running. Closing stops it, and what it has found so far is lost."));
        adw_alert_dialog_add_responses(ADW_ALERT_DIALOG(dialog), "cancel", _("_Cancel"),
                                       "stop", _("_Stop and Close"), NULL);
        adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "stop",
                                                 ADW_RESPONSE_DESTRUCTIVE);
        adw_alert_dialog_set_default_response(ADW_ALERT_DIALOG(dialog), "cancel");
        adw_alert_dialog_set_close_response(ADW_ALERT_DIALOG(dialog), "cancel");
        g_signal_connect(dialog, "response", G_CALLBACK(on_close_answer), self);
        adw_dialog_present(dialog, GTK_WIDGET(window));
        return TRUE;  /* not yet */
    }
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
    for (int i = 0; i < GAUDIT_WINDOW_MAX_TASKS; i++) {
        set_weak(&win->check_rows[i], NULL);
        set_weak(&win->empty_rows[i], NULL);
        set_weak(&win->chevrons[i], NULL);
        g_clear_pointer(&win->results[i].title, g_free);
        g_clear_pointer(&win->results[i].rows, g_ptr_array_unref);
        g_clear_pointer(&win->more_rows[i], g_ptr_array_unref);
        set_weak(&win->task_groups[i], NULL);
    }
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        set_weak(&win->rows[k], NULL);
    for (gsize g = 0; g < N_HOME_GROUPS; g++)
        set_weak(&win->groups[g], NULL);
    set_weak(&win->folder_list, NULL);
    set_weak(&win->folder_title, NULL);
    for (guint i = 0; win->switches != NULL && i < win->switches->len; i++)
        g_object_weak_unref(g_ptr_array_index(win->switches, i), switch_gone, win);
    g_clear_pointer(&win->switches, g_ptr_array_unref);
    g_clear_object(&GAUDIT_WINDOW(object)->settings);
    G_OBJECT_CLASS(gaudit_window_parent_class)->dispose(object);
}

/* --- Construction --------------------------------------------------------- */

static void gaudit_window_class_init(GauditWindowClass *klass)
{
    G_OBJECT_CLASS(klass)->dispose = gaudit_window_dispose;
    /* Every probe in exactly one group, or its row would never be shown. */
    int seen[GAUDIT_PROBE_COUNT] = { 0 };
    for (gsize g = 0; g < N_HOME_GROUPS; g++)
        for (int j = 0; j < home_groups[g].n_kinds; j++)
            seen[home_groups[g].kinds[j]]++;
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        g_warn_if_fail(seen[k] == 1);
}

static void gaudit_window_init(GauditWindow *self)
{
    self->pkg = gaudit_pkg_backend_default();
    self->have_status = FALSE;
    self->worst = GAUDIT_VERDICT_UNKNOWN;
    gaudit_probe_init(self->probes);

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

    /* Sidebar header: the user/administrator switch, then "Audit Center",
     * and the primary menu at the end. */
    AdwHeaderBar *sidebar_header = ADW_HEADER_BAR(adw_header_bar_new());
    adw_header_bar_set_title_widget(sidebar_header,
                                    titled(switch_new(self, FALSE), _("Audit Center"), NULL));
    adw_header_bar_pack_end(sidebar_header, primary_menu_button());

    AdwToolbarView *sidebar_view = ADW_TOOLBAR_VIEW(adw_toolbar_view_new());
    adw_toolbar_view_add_top_bar(sidebar_view, GTK_WIDGET(sidebar_header));
    adw_toolbar_view_set_content(sidebar_view, scroller);
    AdwNavigationPage *sidebar_page =
        adw_navigation_page_new(GTK_WIDGET(sidebar_view), GAUDIT_APP_NAME);
    adw_navigation_page_set_tag(sidebar_page, "sidebar");
    /* The sidebar navigates on its own: a plugin's folder slides in over
     * the root, like folders in Secrets. */
    self->folder = -1;
    self->side_nav = ADW_NAVIGATION_VIEW(adw_navigation_view_new());
    adw_navigation_view_add(self->side_nav, sidebar_page);
    g_signal_connect(self->side_nav, "popped", G_CALLBACK(on_side_popped), self);

    /* Content: a navigation view, so a page 2 can be pushed on top. */
    self->content = ADW_NAVIGATION_VIEW(adw_navigation_view_new());
    g_signal_connect(self->content, "popped", G_CALLBACK(on_content_popped), self);
    g_signal_connect(self->content, "pushed", G_CALLBACK(on_content_pushed), self);
    static const GActionEntry entries[] = {
        { .name = "about-plugin", .activate = on_about_plugin },
        { .name = "plugin-info", .activate = on_plugin_info },
        { .name = "home-info", .activate = on_home_info },
        { .name = "start", .activate = on_start },
    };
    g_action_map_add_action_entries(G_ACTION_MAP(self), entries, G_N_ELEMENTS(entries), self);

    self->split = ADW_NAVIGATION_SPLIT_VIEW(adw_navigation_split_view_new());
    adw_navigation_split_view_set_sidebar(self->split,
        adw_navigation_page_new(GTK_WIDGET(self->side_nav), GAUDIT_APP_NAME));
    adw_navigation_split_view_set_content(self->split,
        adw_navigation_page_new(GTK_WIDGET(self->content), GAUDIT_APP_NAME));
    g_signal_connect(self->split, "notify::collapsed", G_CALLBACK(on_collapsed), self);

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
    (void)elevated;  /* the session's own state, read by each switch */
    switches_update(self);
    fill_check_rows(self);  /* "needs administrator rights" follows the switch */
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

/* --- Home's tasks at the chosen level --------------------------------------- */

guint gaudit_window_home_level(GauditWindow *self)
{
    g_return_val_if_fail(GAUDIT_IS_WINDOW(self), 0);
    return home_level(self);
}

void gaudit_window_task_running(GauditWindow *self, gsize task_index)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    if (task_index >= GAUDIT_WINDOW_MAX_TASKS)
        return;
    self->results[task_index].running = TRUE;
    self->results[task_index].note = NULL;
    fill_check_row(self, task_index);
}

void gaudit_window_task_waiting(GauditWindow *self, gsize task_index, gboolean waiting)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    if (task_index >= GAUDIT_WINDOW_MAX_TASKS)
        return;
    self->results[task_index].waiting = waiting;
    fill_check_row(self, task_index);
}

/* A disc in the accent colour behind the switch while a check waits for
 * administrator rights: not an error, it shows where the switch is. */
void gaudit_window_set_attention(GauditWindow *self, gboolean on)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    self->attention = on;
    switches_update(self);
}

void gaudit_window_task_failed(GauditWindow *self, gsize task_index, gaudit_run_status status)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    if (task_index >= GAUDIT_WINDOW_MAX_TASKS)
        return;
    /* Nothing new: an earlier result stays; otherwise the row says why. */
    self->results[task_index].running = FALSE;
    self->results[task_index].waiting = FALSE;
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    gboolean admin = task_index < n_tasks
                     && gaudit_task_home_needs_admin(&tasks[task_index], home_level(self));
    self->results[task_index].note =
        status == GAUDIT_RUN_CANCELLED && !admin ? _("Not checked: it was stopped")
        : status == GAUDIT_RUN_CANCELLED ? _("Not checked: no password was given, or it was stopped")
        : status == GAUDIT_RUN_DENIED ? _("Not checked: the password was not accepted")
        : status == GAUDIT_RUN_OK ? _("Another check is running. Try again when it has finished")
        : _("The check could not be completed");
    fill_check_row(self, task_index);
}

void gaudit_window_toast(GauditWindow *self, const char *text)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self) && text != NULL);
    GtkWidget *overlay = adw_application_window_get_content(ADW_APPLICATION_WINDOW(self));
    if (ADW_IS_TOAST_OVERLAY(overlay))
        adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(overlay), adw_toast_new(text));
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
