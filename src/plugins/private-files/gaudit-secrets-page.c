/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-secrets-page.h"
#include "gaudit-task-page.h"

/* What the scan's reason ids mean, for the user. Unknown ids are shown as
 * they are. */
static const struct { const char *id; const char *name; } reasons[] = {
    /* The known locations, the same rules Home counts. */
    { "home-writable",       N_("Your home folder can be changed by others") },
    { "tool-mode",           N_("Permissions SSH or GnuPG refuse") },
    { "known-secret",        N_("Stored passwords or keys") },
    /* The deep scan. */
    { "openssh-private-key", N_("SSH private key") },
    { "pem-private-key",     N_("Private key") },
    { "pgp-private-key",     N_("PGP private key") },
    { "putty-private-key",   N_("PuTTY private key") },
    { "gnupg-private-key",   N_("GnuPG private key") },
    { "gnupg1-secret",       N_("Old GnuPG secret keyring") },
    { "pkcs12",              N_("Certificate with private key") },
    { "java-keystore",       N_("Java keystore") },
    { "keepass",             N_("KeePass password database") },
    { "pass",                N_("Password store entry") },
    { "gnome-keyring",       N_("GNOME keyring") },
    { "kwallet",             N_("KDE wallet") },
    { "browser-passwords",   N_("Saved browser passwords") },
    { "crypto-wallet",       N_("Cryptocurrency wallet") },
    { "netrc",               N_("Stored logins (.netrc)") },
    { "pgpass",              N_("PostgreSQL passwords") },
    { "mysql-client",        N_("MySQL login") },
    { "git-credentials",     N_("Git passwords") },
    { "aws-credentials",     N_("AWS keys") },
    { "kube-config",         N_("Kubernetes credentials") },
    { "docker-auth",         N_("Docker logins") },
    { "github-cli",          N_("GitHub login") },
    { "rclone",              N_("Cloud storage logins (rclone)") },
};

static const char *reason_name(const char *id)
{
    for (gsize i = 0; i < G_N_ELEMENTS(reasons); i++)
        if (strcmp(reasons[i].id, id) == 0)
            return _(reasons[i].name);
    return id;
}

char *gaudit_secrets_title(const GauditRunResult *r)
{
    const gaudit_secrets_summary *s = &r->secrets;
    switch (gaudit_secrets_verdict(s)) {
    case GAUDIT_VERDICT_OK:
        if (s->count == 0)
            return g_strdup(_("No secrets found outside the usual places"));
        return g_strdup_printf(ngettext("%u secret found, only you can read it",
                                        "%u secrets found, only you can read them", s->count),
                               s->count);
    case GAUDIT_VERDICT_WARNING: {
        unsigned n = s->others + s->groups;
        return g_strdup_printf(ngettext("%u secret can be read by others",
                                        "%u secrets can be read by others", n), n);
    }
    default:
        return g_strdup(s->status == GAUDIT_SECRETS_OK ? _("The search stopped before the end")
                                                       : _("Your home folder could not be searched"));
    }
}

/* A path that may go into a command as it is: sent unchanged, valid
 * UTF-8, and no quote that would end the shell's quoting. */
static gboolean plain_path(const gaudit_secret_finding *f)
{
    return f->exact && g_utf8_validate(f->path, -1, NULL) && strchr(f->path, '\'') == NULL;
}

static GtkWidget *note(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_add_css_class(label, "dim-label");
    gtk_widget_add_css_class(label, "caption");
    return label;
}

/* The fix for one finding, on a page of its own: what is wrong, and the
 * manual way. A command only for files the user owns (chmod refuses
 * others') whose names were sent exactly. */
static void on_finding_activated(AdwActionRow *row, gpointer user_data)
{
    (void)user_data;
    const gaudit_secret_finding *f = g_object_get_data(G_OBJECT(row), "gaudit-finding");
    GtkWidget *nav = gtk_widget_get_ancestor(GTK_WIDGET(row), ADW_TYPE_NAVIGATION_VIEW);
    if (f == NULL || nav == NULL)
        return;
    const char *shown = adw_preferences_row_get_title(ADW_PREFERENCES_ROW(row));
    gboolean home = strcmp(f->path, ".") == 0;
    g_autofree char *problem = home
        ? g_strdup(_("Others can change what is in your home folder."))
        : f->reach == GAUDIT_SECRET_OTHERS
        ? g_strdup_printf(_("Every account on this computer can read %s."), shown)
        : g_strdup_printf(_("Members of a group can read %s."), shown);
    g_autofree char *command = NULL;
    const char *how, *note_text = NULL;
    if (!f->owned) {
        how = _("It belongs to another account, so only that account or the administrator can "
                "change who may read it.");
    } else if (home) {
        how = _("Run this command in a terminal. Others can still see the names of your files, "
                "but no longer change them.");
        command = g_strdup("chmod go-w ~");
    } else if (!plain_path(f)) {
        how = _("Its name has characters that cannot be shown exactly here, so no command is "
                "given. In the file manager, open its properties and let only you read it.");
    } else {
        how = _("Run this command in a terminal. Afterwards only you can read it; it stays where "
                "it is.");
        command = g_strdup_printf("chmod go-rwx -- ~/'%s'", f->path);
        note_text = _("If you no longer need it, deleting it is safer still.");
    }
    adw_navigation_view_push(ADW_NAVIGATION_VIEW(nav),
                             gaudit_fix_page_new(home ? _("Close Your Home Folder") : _("Make It Private"),
                                                 problem, how, command, note_text));
}

/* The findings of one reach (OWNER also takes the own private group).
 * A finding others can reach is marked with the warning symbol and leads
 * on to its fix; the others get the check mark. */
static GtkWidget *reach_group(const GauditRunResult *r, gaudit_secret_reach reach,
                              const char *title, const char *description)
{
    AdwPreferencesGroup *group = NULL;
    for (unsigned i = 0; i < r->n_secrets; i++) {
        const gaudit_secret_finding *f = &r->secret[i];
        gaudit_secret_reach as = f->reach == GAUDIT_SECRET_OWN_GROUP ? GAUDIT_SECRET_OWNER : f->reach;
        if (as != reach)
            continue;
        if (group == NULL) {
            group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
            adw_preferences_group_set_title(group, title);
            adw_preferences_group_set_description(group, description);
        }
        /* Names come from the disk: plain text, never markup, and made
         * valid UTF-8 for display only. */
        g_autofree char *shown = g_utf8_make_valid(f->path, -1);
        g_autofree char *path = strcmp(f->path, ".") == 0 ? g_strdup("~") : g_strdup_printf("~/%s", shown);
        /* Translators: "<kind of secret> · <permissions>", e.g. "Private key · 0644". */
        g_autofree char *subtitle = g_strdup_printf(_("%s · %04o"), reason_name(f->reason), f->mode);
        AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
        adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
        adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), path);
        adw_action_row_set_subtitle(row, subtitle);
        gboolean problem = as != GAUDIT_SECRET_OWNER;
        adw_action_row_add_prefix(row, gaudit_verdict_icon_new(problem ? GAUDIT_VERDICT_WARNING
                                                                       : GAUDIT_VERDICT_OK));
        if (problem) {
            g_object_set_data_full(G_OBJECT(row), "gaudit-finding", g_memdup2(f, sizeof *f), g_free);
            adw_action_row_add_suffix(row, gtk_image_new_from_icon_name("go-next-symbolic"));
            gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), TRUE);
            g_signal_connect(row, "activated", G_CALLBACK(on_finding_activated), NULL);
        } else {
            adw_preferences_row_set_title_selectable(ADW_PREFERENCES_ROW(row), TRUE);
        }
        adw_preferences_group_add(group, GTK_WIDGET(row));
    }
    return group != NULL ? GTK_WIDGET(group) : NULL;
}

void gaudit_secrets_show(AdwStatusPage *status, const GauditRunResult *r)
{
    const gaudit_secrets_summary *s = &r->secrets;
    gaudit_verdict verdict = gaudit_secrets_verdict(s);
    g_autofree char *title = gaudit_secrets_title(r);
    const char *icon = verdict == GAUDIT_VERDICT_OK ? "gaudit-status-high-symbolic"
                     : verdict == GAUDIT_VERDICT_WARNING ? "gaudit-status-medium-symbolic"
                     : "gaudit-status-unknown-symbolic";
    const char *description = verdict == GAUDIT_VERDICT_OK
        ? _("Secrets only you can read are normal. This means none were found that others can "
            "read, not that every secret was found.")
        : verdict == GAUDIT_VERDICT_WARNING
        ? _("Anyone who can use these accounts can copy them. Open each one marked with a "
            "warning to see how to close it.")
        : _("Nothing is known about the files that were not searched.");
    adw_status_page_set_paintable(status, NULL);
    adw_status_page_set_icon_name(status, icon);
    adw_status_page_set_title(status, title);
    adw_status_page_set_description(status, description);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    GtkWidget *others = reach_group(r, GAUDIT_SECRET_OTHERS, _("Every account can read these"),
        _("Any other account on this computer can read them, including programs running as "
          "those accounts."));
    if (others != NULL)
        gtk_box_append(GTK_BOX(box), others);
    GtkWidget *groups = reach_group(r, GAUDIT_SECRET_GROUP, _("Members of a group can read these"),
        _("Accounts in a group that has access to the file, or to a folder on the way, can read "
          "them."));
    if (groups != NULL)
        gtk_box_append(GTK_BOX(box), groups);
    GtkWidget *mine = reach_group(r, GAUDIT_SECRET_OWNER, _("Only you can read these"),
        _("This is how secrets should be kept. Listed so you know where they are."));
    if (mine != NULL)
        gtk_box_append(GTK_BOX(box), mine);
    if (s->shown < s->count) {
        g_autofree char *more = g_strdup_printf(_("Showing %u of %u files."), s->shown, s->count);
        gtk_box_append(GTK_BOX(box), note(more));
    }
    if (s->truncated)
        gtk_box_append(GTK_BOX(box), note(
            _("Your home folder has more files than the search goes through, so it stopped "
              "before the end.")));
    if (gtk_widget_get_first_child(box) == NULL) {
        g_object_ref_sink(box);
        g_object_unref(box);
        return;
    }
    GtkWidget *clamp = adw_clamp_new();
    adw_clamp_set_child(ADW_CLAMP(clamp), box);
    adw_status_page_set_child(status, clamp);
}
