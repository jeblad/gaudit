/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-window.h"
#include "gaudit-task.h"
#include "gaudit-task-page.h"

struct _GauditWindow {
    AdwApplicationWindow parent_instance;

    AdwNavigationSplitView *split;
    GtkListBox *sidebar;
    AdwNavigationView *content;

    const gaudit_pkg_backend *pkg;
    gboolean have_status;
    gaudit_probe_result probes[GAUDIT_PROBE_COUNT];
    gaudit_verdict worst;
};

G_DEFINE_FINAL_TYPE(GauditWindow, gaudit_window, ADW_TYPE_APPLICATION_WINDOW)

static void navigate(GauditWindow *self, int index, gboolean show_content);

/* --- Home ----------------------------------------------------------------- */

static void set_summary(AdwStatusPage *status, gboolean have_status, gaudit_verdict worst)
{
    const char *icon, *title, *description;

    if (!have_status) {
        icon = "dialog-question-symbolic";
        title = _("No checks have been run");
        description = NULL;
    } else {
        switch (worst) {
        case GAUDIT_VERDICT_OK:
            icon = "security-high-symbolic";
            title = _("No signs of problems found");
            /* Translators: Keep the meaning: a clean result is not a guarantee. */
            description = _("This does not prove the computer is safe, "
                            "only that the checks found nothing wrong.");
            break;
        case GAUDIT_VERDICT_WARNING:
            icon = "security-medium-symbolic";
            title = _("Some things need attention");
            description = NULL;
            break;
        case GAUDIT_VERDICT_CRITICAL:
            icon = "security-low-symbolic";
            title = _("Serious problems found");
            description = NULL;
            break;
        case GAUDIT_VERDICT_UNKNOWN:
        default:
            icon = "dialog-warning-symbolic";
            title = _("Some checks could not be completed");
            description = NULL;
            break;
        }
    }

    adw_status_page_set_icon_name(status, icon);
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
                                    r->detail != NULL ? r->detail : "?");
        return _("Package system");
    }

    case GAUDIT_PROBE_SNAP:
        if (r->missing_capability != NULL) {
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
        if (r->missing_capability != NULL) {
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
    copy.missing_capability = NULL;
    return probe_text(&copy, &ignored);
}

static void on_missing_row_activated(AdwActionRow *row, gpointer user_data)
{
    GauditWindow *self = GAUDIT_WINDOW(user_data);
    const char *capability = g_object_get_data(G_OBJECT(row), "gaudit-capability");
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

static AdwNavigationPage *build_home(GauditWindow *self)
{
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
    set_summary(status, self->have_status, self->worst);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);

    if (self->have_status) {
        /* Host and distribution come from the system and are shown as
         * plain text, never as markup. */
        char host[256], distro[256], full[256];
        gaudit_system_describe(host, sizeof host, distro, sizeof distro, full, sizeof full);
        /* After the dash: how gAudit treats the system, i.e. which backend
         * does the checks. Not read from the distribution. */
        const char *family = g_strcmp0(self->pkg->name, "debian") == 0 ? _("Debian")
                                                                       : _("generic");
        /* Translators: "<distribution> – <how gAudit treats it>", e.g. "Ubuntu – Debian". */
        g_autofree char *system = distro[0] != '\0'
            ? g_strdup_printf(_("%s – %s"), distro, family)
            : g_strdup(_("Unknown"));
        /* Translators: "Status: <host name> (<system>)". */
        g_autofree char *heading = g_strdup_printf(_("Status: %s (%s)"),
                                                   host[0] != '\0' ? host : _("this computer"),
                                                   system);
        GtkWidget *heading_label = gtk_label_new(heading);
        gtk_label_set_xalign(GTK_LABEL(heading_label), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(heading_label), TRUE);
        gtk_widget_add_css_class(heading_label, "heading");
        /* The version matters (releases go out of support), so it is one
         * hover away. Tooltips are plain text here. */
        if (full[0] != '\0')
            gtk_widget_set_tooltip_text(heading_label, full);
        gtk_box_append(GTK_BOX(box), heading_label);

        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_description(group,
            _("A quick look that does not need your password."));
        for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
            const gaudit_probe_result *probe = &self->probes[k];
            if (!probe->applicable)
                continue;
            g_autofree char *subtitle = NULL;
            const char *title = probe_text(probe, &subtitle);
            AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
            /* Subtitles carry data from the system: never interpret markup. */
            adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
            adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
            adw_action_row_set_subtitle(row, subtitle);
            adw_action_row_add_prefix(row, verdict_icon(probe->verdict));
            const gaudit_capability *missing = probe->missing_capability == NULL || self->pkg->capability == NULL
                ? NULL : self->pkg->capability(probe->missing_capability);
            /* Only lead on when the backend knows which packages to install. */
            if (missing != NULL && missing->packages != NULL && missing->packages[0] != NULL) {
                adw_action_row_add_suffix(row, gtk_image_new_from_icon_name("go-next-symbolic"));
                gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
                g_object_set_data(G_OBJECT(row), "gaudit-capability",
                                  (gpointer)probe->missing_capability);
                g_signal_connect(row, "activated", G_CALLBACK(on_missing_row_activated), self);
            }
            adw_preferences_group_add(group, GTK_WIDGET(row));
        }
        gtk_box_append(GTK_BOX(box), GTK_WIDGET(group));
    }

    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    if (n_tasks > 0) {
        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(group, _("Checks"));
        for (gsize i = 0; i < n_tasks; i++) {
            const GauditTaskInfo *task = &tasks[i];
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

/* --- Construction --------------------------------------------------------- */

static void gaudit_window_class_init(GauditWindowClass *klass)
{
    (void)klass;
}

static void gaudit_window_init(GauditWindow *self)
{
    self->pkg = gaudit_pkg_backend_default();
    self->have_status = FALSE;
    self->worst = GAUDIT_VERDICT_UNKNOWN;

    gtk_window_set_title(GTK_WINDOW(self), GAUDIT_APP_NAME);
    gtk_window_set_default_size(GTK_WINDOW(self), 900, 600);
    gtk_widget_set_size_request(GTK_WIDGET(self), 360, 294);

    /* Sidebar: Home first, then one row per task. */
    self->sidebar = GTK_LIST_BOX(gtk_list_box_new());
    gtk_widget_add_css_class(GTK_WIDGET(self->sidebar), "navigation-sidebar");
    gtk_list_box_append(self->sidebar,
                        sidebar_row("go-home-symbolic", _("Home"), _("Overall status")));
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
    AdwHeaderBar *sidebar_header = ADW_HEADER_BAR(adw_header_bar_new());
    adw_header_bar_set_show_title(sidebar_header, FALSE);
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

GauditWindow *gaudit_window_new(GtkApplication *app)
{
    return g_object_new(GAUDIT_TYPE_WINDOW, "application", app, NULL);
}

void gaudit_window_show_status(GauditWindow *self,
                               const gaudit_probe_result results[GAUDIT_PROBE_COUNT],
                               gaudit_verdict worst)
{
    g_return_if_fail(GAUDIT_IS_WINDOW(self));
    g_return_if_fail(results != NULL);

    memcpy(self->probes, results, sizeof self->probes);
    self->have_status = TRUE;
    self->worst = worst;

    AdwNavigationPage *visible = adw_navigation_view_get_visible_page(self->content);
    if (visible != NULL && g_strcmp0(adw_navigation_page_get_tag(visible), "home") == 0)
        navigate(self, 0, FALSE);
}
