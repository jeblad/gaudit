/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-run-page.h"
#include "gaudit-task-page.h"

AdwNavigationPage *gaudit_page_wrap(GtkWidget *content, const char *title, const char *tag)
{
    AdwToolbarView *toolbar = ADW_TOOLBAR_VIEW(adw_toolbar_view_new());
    adw_toolbar_view_add_top_bar(toolbar, adw_header_bar_new());
    adw_toolbar_view_set_content(toolbar, content);

    AdwNavigationPage *page = adw_navigation_page_new(GTK_WIDGET(toolbar), title);
    if (tag != NULL)
        adw_navigation_page_set_tag(page, tag);
    return page;
}

static void show_toast(GtkWidget *widget, const char *text)
{
    GtkWidget *overlay = gtk_widget_get_ancestor(widget, ADW_TYPE_TOAST_OVERLAY);
    if (overlay != NULL)
        adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(overlay), adw_toast_new(text));
}

static GtkWidget *wrapped_label(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    return label;
}

/* --- Shared pieces --------------------------------------------------------- */

GtkWidget *gaudit_verdict_icon_new(gaudit_verdict verdict)
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

AdwNavigationPage *gaudit_fix_page_new(const char *title, const char *problem, const char *how,
                                       const char *command, const char *note)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 24);
    gtk_widget_set_margin_bottom(box, 24);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    GtkWidget *what = wrapped_label(problem);
    gtk_widget_add_css_class(what, "title-4");
    gtk_box_append(GTK_BOX(box), what);
    gtk_box_append(GTK_BOX(box), wrapped_label(how));
    if (command != NULL)
        gtk_box_append(GTK_BOX(box), gaudit_command_field_new(command));
    if (note != NULL) {
        GtkWidget *small = wrapped_label(note);
        gtk_widget_add_css_class(small, "dim-label");
        gtk_widget_add_css_class(small, "caption");
        gtk_box_append(GTK_BOX(box), small);
    }
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), clamp);
    return gaudit_page_wrap(scroller, title, "fix");
}

static void on_teaser_expanded(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    (void)pspec; (void)user_data;
    AdwExpanderRow *row = ADW_EXPANDER_ROW(object);
    gboolean open = adw_expander_row_get_expanded(row);
    /* The row centres its arrow, so it moves down as the text grows.
     * Accepted: pinning it reached into libadwaita and looked odd. */
    /* Closed: one line of the first paragraph, ending in "…". Open: the
     * whole text in place, so the reader goes on from where it was cut. */
    const char *text = g_object_get_data(object, "gaudit-text");
    if (open) {
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), text);
    } else {
        const char *nl = strchr(text, '\n');
        g_autofree char *first = nl != NULL ? g_strndup(text, (gsize)(nl - text)) : g_strdup(text);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), first);
    }
    adw_expander_row_set_title_lines(row, open ? 0 : 1);
}

GtkWidget *gaudit_teaser_row_new(const char *text)
{
    AdwExpanderRow *row = ADW_EXPANDER_ROW(adw_expander_row_new());
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    g_object_set_data_full(G_OBJECT(row), "gaudit-text", g_strdup(text), g_free);
    g_signal_connect(row, "notify::expanded", G_CALLBACK(on_teaser_expanded), NULL);
    on_teaser_expanded(G_OBJECT(row), NULL, NULL);
    return GTK_WIDGET(row);
}

GtkWidget *gaudit_action_button_new(const char *label, gboolean opens_page, gboolean is_default)
{
    GtkWidget *button = gtk_button_new();
    /* Label, then the chevron, in reading order: the box and the icon
     * (go-next has an -rtl variant) mirror themselves in right-to-left. */
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_halign(content, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(content), gtk_label_new(label));
    if (opens_page) {
        GtkWidget *chevron = gtk_image_new_from_icon_name("go-next-symbolic");
        gtk_accessible_update_property(GTK_ACCESSIBLE(chevron),
                                       GTK_ACCESSIBLE_PROPERTY_LABEL, _("Opens a new page"), -1);
        gtk_box_append(GTK_BOX(content), chevron);
    }
    gtk_button_set_child(GTK_BUTTON(button), content);
    gtk_widget_add_css_class(button, "pill");
    if (is_default)
        gtk_widget_add_css_class(button, "suggested-action");
    /* At the end, where "forward" is (right in left-to-right, left in
     * right-to-left); Undo, going back, will sit at the start. */
    gtk_widget_set_halign(button, GTK_ALIGN_END);
    return button;
}

/* --- Page 2: run ---------------------------------------------------------- */

static void on_start_clicked(GtkButton *button, gpointer user_data)
{
    const GauditTaskInfo *task = user_data;
    GtkWidget *nav = gtk_widget_get_ancestor(GTK_WIDGET(button), ADW_TYPE_NAVIGATION_VIEW);
    g_return_if_fail(nav != NULL);

    /* TODO: hand the selected parameters to the orchestrator. */
    adw_navigation_view_push(ADW_NAVIGATION_VIEW(nav), gaudit_run_page_new(task));
}

/* --- Page 1: settings ----------------------------------------------------- */

static GtkWidget *build_settings(const GauditTaskInfo *task)
{
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());

    AdwPreferencesGroup *about = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_description(about, _(task->summary));
    adw_preferences_group_add(about, gaudit_teaser_row_new(_(task->details)));
    adw_preferences_page_add(page, about);

    AdwPreferencesGroup *params = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(params, _("What to check"));
    for (gsize i = 0; i < task->n_params; i++) {
        const GauditTaskParam *p = &task->params[i];
        AdwSwitchRow *row = ADW_SWITCH_ROW(adw_switch_row_new());
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), _(p->title));
        adw_action_row_set_subtitle(ADW_ACTION_ROW(row), _(p->subtitle));
        adw_switch_row_set_active(row, p->default_value);
        g_object_set_data(G_OBJECT(row), "gaudit-param", (gpointer)p->id);
        adw_preferences_group_add(params, GTK_WIDGET(row));
    }
    if (task->n_params > 0)
        adw_preferences_page_add(page, params);
    else
        g_object_unref(g_object_ref_sink(params));  /* nothing to set */

    AdwPreferencesGroup *actions = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    /* Opens page 2; the page's one action, so the default. */
    GtkWidget *start = gaudit_action_button_new(_("Start"), TRUE, TRUE);
    g_signal_connect(start, "clicked", G_CALLBACK(on_start_clicked), (gpointer)task);
    adw_preferences_group_add(actions, start);
    adw_preferences_page_add(page, actions);

    return GTK_WIDGET(page);
}

/* --- Missing software ----------------------------------------------------- */

/* What is copied is the text in the field, as the user sees it, never
 * data kept beside it: changing what gets copied then means changing what
 * is shown. It is also compared with the command the field was made from,
 * and a difference means something has changed the field: nothing is
 * copied then. */
static void on_copy_clicked(GtkButton *button, gpointer user_data)
{
    GtkLabel *label = GTK_LABEL(user_data);
    const char *shown = gtk_label_get_text(label);
    const char *expected = g_object_get_data(G_OBJECT(button), "gaudit-command");
    if (shown == NULL || g_strcmp0(shown, expected) != 0) {
        g_warning("gaudit: the command field no longer shows its command; not copied");
        show_toast(GTK_WIDGET(button), _("The command shown has changed, so it was not copied"));
        return;
    }
    gdk_clipboard_set_text(gtk_widget_get_clipboard(GTK_WIDGET(button)), shown);
    show_toast(GTK_WIDGET(button), _("Command copied"));
}

GtkWidget *gaudit_command_field_new(const char *command_text)
{
    char *command = g_strdup(command_text);
    /* The command field: read-only, selectable, always left-to-right.
     * Plain text: never markup, so what is shown is the command itself. */
    GtkWidget *field = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_add_css_class(field, "card");
    gtk_widget_set_direction(field, GTK_TEXT_DIR_LTR);
    GtkWidget *cmd_label = gtk_label_new(command);
    gtk_label_set_use_markup(GTK_LABEL(cmd_label), FALSE);
    gtk_label_set_use_underline(GTK_LABEL(cmd_label), FALSE);
    gtk_label_set_selectable(GTK_LABEL(cmd_label), TRUE);
    gtk_label_set_wrap(GTK_LABEL(cmd_label), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(cmd_label), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(cmd_label), 0.0f);
    gtk_widget_add_css_class(cmd_label, "monospace");
    gtk_widget_set_hexpand(cmd_label, TRUE);
    gtk_widget_set_margin_top(cmd_label, 12);
    gtk_widget_set_margin_bottom(cmd_label, 12);
    gtk_widget_set_margin_start(cmd_label, 12);
    gtk_box_append(GTK_BOX(field), cmd_label);

    GtkWidget *copy = gtk_button_new_from_icon_name("edit-copy-symbolic");
    gtk_widget_add_css_class(copy, "flat");
    gtk_widget_set_valign(copy, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_end(copy, 6);
    gtk_widget_set_tooltip_text(copy, _("Copy command"));
    gtk_accessible_update_property(GTK_ACCESSIBLE(copy),
                                   GTK_ACCESSIBLE_PROPERTY_LABEL, _("Copy command"), -1);
    g_object_set_data_full(G_OBJECT(copy), "gaudit-command", command, g_free);
    /* The label lives as long as the button: both are children of field. */
    g_signal_connect(copy, "clicked", G_CALLBACK(on_copy_clicked), cmd_label);
    gtk_box_append(GTK_BOX(field), copy);
    return field;
}


static void on_install_clicked(GtkButton *button, gpointer user_data)
{
    (void)user_data;
    /* TODO: install via PackageKit (D-Bus). Fallback: pkexec with the
     * backend's fixed argv, and say clearly in the UI that it is a fallback.
     * As with copying: before installing, the field's shown text must equal
     * the command built from the backend's fixed table; if not, install
     * nothing. The packages come from the table, never parsed from the field. */
    show_toast(GTK_WIDGET(button), _("Installing is not implemented yet."));
}

static GtkWidget *build_missing(const gaudit_pkg_backend *pkg, GPtrArray *missing)
{
    g_ptr_array_add(missing, NULL);  /* NULL-terminate for g_strjoinv */
    g_autofree char *list = g_strjoinv(", ", (char **)missing->pdata);
    g_autofree char *names = g_strjoinv(" ", (char **)missing->pdata);
    g_autofree char *command = g_strjoin(" ", pkg->manual_install_command, names, NULL);

    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
    adw_status_page_set_icon_name(status, "system-software-install-symbolic");
    adw_status_page_set_title(status, _("Software is missing"));
    /* Translators: %s is a comma-separated list of package names. */
    g_autofree char *description =
        g_strdup_printf(_("This check needs software that is not installed: %s."), list);
    adw_status_page_set_description(status, description);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);

    gtk_box_append(GTK_BOX(box),
                   wrapped_label(_("You can install it with the button below, or copy "
                                   "this command and run it in a terminal yourself:")));

    gtk_box_append(GTK_BOX(box), gaudit_command_field_new(command));

    GtkWidget *install = gtk_button_new_with_label(_("Install"));
    gtk_widget_add_css_class(install, "pill");
    gtk_widget_add_css_class(install, "suggested-action");
    gtk_widget_set_halign(install, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(install, 12);
    g_signal_connect(install, "clicked", G_CALLBACK(on_install_clicked), NULL);
    gtk_box_append(GTK_BOX(box), install);

    GtkWidget *note = wrapped_label(_("Installing uses the system's software service "
                                      "and asks for your password."));
    gtk_label_set_xalign(GTK_LABEL(note), 0.5f);
    gtk_label_set_justify(GTK_LABEL(note), GTK_JUSTIFY_CENTER);
    gtk_widget_add_css_class(note, "dim-label");
    gtk_widget_add_css_class(note, "caption");
    gtk_box_append(GTK_BOX(box), note);

    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(status, clamp);
    return GTK_WIDGET(status);
}

static GtkWidget *build_unsupported(void)
{
    AdwStatusPage *status = ADW_STATUS_PAGE(adw_status_page_new());
    adw_status_page_set_icon_name(status, "dialog-information-symbolic");
    adw_status_page_set_title(status, _("Not available on this system"));
    adw_status_page_set_description(status,
        _("This check is not supported on this operating system yet."));
    return GTK_WIDGET(status);
}

AdwNavigationPage *gaudit_missing_software_page_new(const gaudit_pkg_backend *pkg,
                                                    const char *title,
                                                    const char *const *packages)
{
    g_autoptr(GPtrArray) missing = g_ptr_array_new();
    for (const char *const *p = packages; p != NULL && *p != NULL; p++)
        g_ptr_array_add(missing, (gpointer)*p);
    return gaudit_page_wrap(build_missing(pkg, missing), title, "missing-software");
}

AdwNavigationPage *gaudit_task_page_new(const GauditTaskInfo *task,
                                       const gaudit_pkg_backend *pkg)
{
    g_autoptr(GPtrArray) missing = gaudit_task_missing_packages(task, pkg);
    GtkWidget *content;

    if (missing == NULL)
        content = build_unsupported();
    else if (missing->len > 0)
        content = build_missing(pkg, missing);
    else
        content = build_settings(task);

    return gaudit_page_wrap(content, _(task->title), task->id);
}
