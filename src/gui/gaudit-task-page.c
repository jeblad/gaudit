/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

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
    AdwExpanderRow *more = ADW_EXPANDER_ROW(adw_expander_row_new());
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(more), _("More about this"));
    GtkWidget *details = wrapped_label(_(task->details));
    gtk_widget_set_margin_top(details, 12);
    gtk_widget_set_margin_bottom(details, 12);
    gtk_widget_set_margin_start(details, 12);
    gtk_widget_set_margin_end(details, 12);
    adw_expander_row_add_row(more, details);
    adw_preferences_group_add(about, GTK_WIDGET(more));
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
    GtkWidget *start = gtk_button_new_with_label(_("Start"));
    gtk_widget_add_css_class(start, "pill");
    gtk_widget_add_css_class(start, "suggested-action");
    gtk_widget_set_halign(start, GTK_ALIGN_CENTER);
    g_signal_connect(start, "clicked", G_CALLBACK(on_start_clicked), (gpointer)task);
    adw_preferences_group_add(actions, start);
    adw_preferences_page_add(page, actions);

    return GTK_WIDGET(page);
}

/* --- Missing software ----------------------------------------------------- */

static void on_copy_clicked(GtkButton *button, gpointer user_data)
{
    (void)user_data;
    const char *command = g_object_get_data(G_OBJECT(button), "gaudit-command");
    gdk_clipboard_set_text(gtk_widget_get_clipboard(GTK_WIDGET(button)), command);
    show_toast(GTK_WIDGET(button), _("Command copied"));
}

static void on_install_clicked(GtkButton *button, gpointer user_data)
{
    (void)user_data;
    /* TODO: install via PackageKit (D-Bus). Fallback: pkexec with the
     * backend's fixed argv, and say clearly in the UI that it is a fallback. */
    show_toast(GTK_WIDGET(button), _("Installing is not implemented yet."));
}

static GtkWidget *build_missing(const gaudit_pkg_backend *pkg, GPtrArray *missing)
{
    g_ptr_array_add(missing, NULL);  /* NULL-terminate for g_strjoinv */
    g_autofree char *list = g_strjoinv(", ", (char **)missing->pdata);
    g_autofree char *names = g_strjoinv(" ", (char **)missing->pdata);
    char *command = g_strjoin(" ", pkg->manual_install_command, names, NULL);

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

    /* The command field: read-only, selectable, always left-to-right. */
    GtkWidget *field = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_add_css_class(field, "card");
    gtk_widget_set_direction(field, GTK_TEXT_DIR_LTR);
    GtkWidget *cmd_label = gtk_label_new(command);
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
    g_signal_connect(copy, "clicked", G_CALLBACK(on_copy_clicked), NULL);
    gtk_box_append(GTK_BOX(field), copy);
    gtk_box_append(GTK_BOX(box), field);

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
