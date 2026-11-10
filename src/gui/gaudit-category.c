/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-category.h"
#include "gaudit-task-page.h"

static const GauditCategoryTool firewall_tools[] = {
    { "ufw", N_("ufw (Uncomplicated Firewall)"),
      N_("Simple to set up, and the usual choice on Ubuntu, Debian and Arch. Once switched "
         "on, it blocks incoming connections unless you allow them."),
      "sudo ufw enable" },
    { "firewalld", N_("firewalld"),
      N_("The usual firewall on Fedora and openSUSE. It knows different zones, such as home "
         "and public networks, and blocks incoming connections the zone does not allow."),
      "sudo systemctl enable --now firewalld" },
};

static const GauditCategoryTool antivirus_tools[] = {
    { "clamav", N_("ClamAV"),
      N_("An open-source virus scanner. It finds known malware in files, also malware for "
         "other systems that you might otherwise pass on."),
      NULL },
};

static const GauditCategory categories[] = {
    { "status.firewall", N_("Choose a Firewall"),
      N_("A firewall decides which connections from other computers may reach this one. "
         "Install one of these, then switch it on."),
      firewall_tools, G_N_ELEMENTS(firewall_tools) },
    { "status.antivirus", N_("Choose an Antivirus Program"),
      N_("An antivirus program looks for known malware in files."),
      antivirus_tools, G_N_ELEMENTS(antivirus_tools) },
};

const GauditCategory *gaudit_category_for_probe(const char *probe_id)
{
    for (gsize i = 0; probe_id != NULL && i < G_N_ELEMENTS(categories); i++)
        if (g_strcmp0(categories[i].probe_id, probe_id) == 0)
            return &categories[i];
    return NULL;
}

static const gaudit_capability *tool_capability(const GauditCategoryTool *tool,
                                                const gaudit_pkg_backend *pkg)
{
    return pkg != NULL && pkg->capability != NULL ? pkg->capability(tool->capability) : NULL;
}

const char *gaudit_category_enable_command(const GauditCategory *category,
                                           const gaudit_pkg_backend *pkg)
{
    for (gsize i = 0; category != NULL && i < category->n_tools; i++)
        if (gaudit_capability_present(tool_capability(&category->tools[i], pkg)))
            return category->tools[i].enable;
    return NULL;
}

static gboolean is_recommended(const GauditCategoryTool *tool, const gaudit_pkg_backend *pkg)
{
    for (const char *const *r = pkg->recommended; r != NULL && *r != NULL; r++)
        if (g_strcmp0(*r, tool->capability) == 0)
            return TRUE;
    return FALSE;
}

static GtkWidget *label(const char *text, const char *css)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    if (css != NULL)
        gtk_widget_add_css_class(l, css);
    return l;
}

AdwNavigationPage *gaudit_category_page_new(const GauditCategory *category,
                                            const gaudit_pkg_backend *pkg)
{
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());
    AdwPreferencesGroup *intro = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_description(intro, _(category->intro));
    adw_preferences_page_add(page, intro);

    /* The recommended one first. */
    int shown = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (gsize i = 0; i < category->n_tools; i++) {
            const GauditCategoryTool *tool = &category->tools[i];
            if (is_recommended(tool, pkg) != (pass == 0))
                continue;
            const gaudit_capability *cap = tool_capability(tool, pkg);
            /* Only tools the backend knows how to install. */
            if (cap == NULL || cap->packages == NULL || cap->packages[0] == NULL)
                continue;

            AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
            adw_preferences_group_set_title(group, _(tool->name));
            if (pass == 0) {
                /* Icon then text in reading order; the box mirrors itself
                 * in right-to-left languages. */
                GtkWidget *tag = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
                gtk_widget_add_css_class(tag, "recommended-badge");
                gtk_widget_set_valign(tag, GTK_ALIGN_CENTER);
                gtk_box_append(GTK_BOX(tag), gtk_image_new_from_icon_name("dialog-information-symbolic"));
                GtkWidget *text = gtk_label_new(_("Recommended"));
                gtk_widget_add_css_class(text, "caption-heading");
                gtk_box_append(GTK_BOX(tag), text);
                adw_preferences_group_set_header_suffix(group, tag);
            }
            GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
            gtk_box_append(GTK_BOX(box), label(_(tool->description), NULL));

            g_autofree char *names = g_strjoinv(" ", (char **)cap->packages);
            g_autofree char *install = g_strjoin(" ", pkg->manual_install_command, names, NULL);
            gtk_box_append(GTK_BOX(box), label(_("Install it with this command in a terminal:"), NULL));
            gtk_box_append(GTK_BOX(box), gaudit_command_field_new(install));
            if (tool->enable != NULL) {
                gtk_box_append(GTK_BOX(box), label(_("Then switch it on:"), NULL));
                gtk_box_append(GTK_BOX(box), gaudit_command_field_new(tool->enable));
            }
            adw_preferences_group_add(group, box);
            adw_preferences_page_add(page, group);
            shown++;
        }
    }
    if (shown == 0) {
        AdwPreferencesGroup *none = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_description(none,
            _("gAudit does not know how to install these on this system yet."));
        adw_preferences_page_add(page, none);
    }
    return gaudit_page_wrap(GTK_WIDGET(page), _(category->title), "category");
}
