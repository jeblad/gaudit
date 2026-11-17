/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>

#include "gaudit-environ-page.h"
#include "gaudit-environ.h"
#include "gaudit-task-page.h"

/* A removed entry split: its name, and its value. */
static void split(const char *entry, char *name, size_t name_len, const char **value)
{
    size_t n = strcspn(entry, "=");
    g_snprintf(name, name_len, "%.*s", (int)n, entry);
    *value = entry[n] == '=' ? entry + n + 1 : "";
}

/* The parts of a value: ':' between, and for LD_PRELOAD ' ' too. Empty
 * parts are kept: in a search path, an empty part is the folder the
 * program is started in. */
static char **parts(const char *name, const char *value)
{
    const char *seps = strcmp(name, "LD_PRELOAD") == 0 ? ": " : ":";
    if (gaudit_environ_kind(name) == GAUDIT_ENV_MODULES)
        seps = ":,";
    return g_strsplit_set(value, seps, 64);
}

/* Who can change one part, judged; a module named without a folder is the
 * system's. */
static void judge_part(const char *name, const char *part, gaudit_env_judgement *j)
{
    memset(j, 0, sizeof *j);
    if (gaudit_environ_kind(name) == GAUDIT_ENV_MODULES && strchr(part, '/') == NULL) {
        j->reach = GAUDIT_ENV_ROOT_ONLY;
        return;
    }
    gaudit_environ_judge_path(part, j);
}

static gboolean entry_open(const char *entry)
{
    char name[128];
    const char *value;
    split(entry, name, sizeof name, &value);
    if (gaudit_environ_kind(name) == GAUDIT_ENV_OTHER)
        return FALSE;
    g_auto(GStrv) p = parts(name, value);
    for (guint i = 0; p[i] != NULL; i++) {
        /* LD_PRELOAD's separators may leave empty parts that mean nothing. */
        if (p[i][0] == '\0' && strcmp(name, "LD_PRELOAD") == 0)
            continue;
        gaudit_env_judgement j;
        judge_part(name, p[i], &j);
        if (j.reach != GAUDIT_ENV_ROOT_ONLY)
            return TRUE;
    }
    return FALSE;
}

gaudit_verdict gaudit_environ_verdict(void)
{
    size_t n = gaudit_environ_removed_count();
    if (n == 0)
        return GAUDIT_VERDICT_UNKNOWN;
    for (size_t i = 0; i < n; i++)
        if (entry_open(gaudit_environ_removed_entry(i)))
            return GAUDIT_VERDICT_WARNING;
    return GAUDIT_VERDICT_OK;
}

static const char *what_it_does(const char *name)
{
    if (strcmp(name, "LD_PRELOAD") == 0)
        return _("Loads these libraries into every program started with it, before the "
                 "program's own.");
    if (strcmp(name, "LD_LIBRARY_PATH") == 0)
        return _("Programs look for their libraries in these folders before the system's own.");
    if (strcmp(name, "LD_AUDIT") == 0)
        return _("Loads these libraries to follow how a program loads others.");
    switch (gaudit_environ_kind(name)) {
    case GAUDIT_ENV_PATHS:
        return _("Programs that use GTK, GIO, GStreamer or GObject look for modules or data here "
                 "before the system's own.");
    case GAUDIT_ENV_MODULES:
        return _("GTK loads these modules into every window. A module named without a folder is "
                 "taken from the system's folders.");
    default:
        return _("Changes how programs are loaded or run, but loads no code of its own.");
    }
}

static AdwActionRow *row_new(gaudit_verdict verdict, const char *title, const char *subtitle)
{
    AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
    /* Values from the caller's environment: plain text, never markup. */
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    if (subtitle != NULL) {
        adw_action_row_set_subtitle(row, subtitle);
        adw_action_row_set_subtitle_lines(row, 0);
    }
    adw_action_row_add_prefix(row, gaudit_verdict_icon_new(verdict));
    return row;
}

/* Who can change a part, in plain words. */
static char *reach_text(const gaudit_env_judgement *j)
{
    switch (j->reach) {
    case GAUDIT_ENV_ROOT_ONLY:
        return g_strdup(_("Only the administrator can change it"));
    case GAUDIT_ENV_OWNER: {
        struct passwd *pw = getpwuid(j->owner);
        g_autofree char *who = pw != NULL ? g_strdup(pw->pw_name)
                                          : g_strdup_printf("%u", (unsigned)j->owner);
        /* Translators: "<folder or file> belongs to <account>, not the administrator". */
        return g_strdup_printf(_("%s belongs to %s, not the administrator"), j->where, who);
    }
    case GAUDIT_ENV_GROUP: {
        struct group *gr = getgrgid(j->group);
        char members[256];
        gaudit_environ_group_members(j->group, members, sizeof members);
        g_autofree char *grp = gr != NULL ? g_strdup(gr->gr_name)
                                          : g_strdup_printf("%u", (unsigned)j->group);
        /* Translators: "<folder> can be changed by the accounts in the group <group>: <accounts>". */
        return g_strdup_printf(_("%s can be changed by the accounts in the group %s: %s"),
                               j->where, grp, members);
    }
    case GAUDIT_ENV_OTHERS:
        /* Translators: %s is a folder or file. */
        return g_strdup_printf(_("%s can be changed by every account"), j->where);
    case GAUDIT_ENV_EMPTY:
        return g_strdup(_("An empty entry, from a colon first, last or two in a row: programs "
                          "then look in the folder they are started from, before the system's "
                          "own. That folder is yours, so anything on your account can put code "
                          "there."));
    case GAUDIT_ENV_RELATIVE:
    default:
        return g_strdup(_("Not a full path: it is looked for from the folder the program is "
                          "started from, which can be any folder."));
    }
}

static gboolean plain_name(const char *name)
{
    if (*name == '\0')
        return FALSE;
    for (const char *c = name; *c != '\0'; c++)
        if (!g_ascii_isalnum(*c) && *c != '_')
            return FALSE;
    return TRUE;
}

#define WIKI_PAGE GAUDIT_WEBSITE "/wiki/This-Computer#settings-that-load-code"

static void on_wiki(AdwActionRow *row, gpointer user_data)
{
    (void)user_data;
    GtkUriLauncher *launcher = gtk_uri_launcher_new(WIKI_PAGE);
    GtkRoot *root = gtk_widget_get_root(GTK_WIDGET(row));
    gtk_uri_launcher_launch(launcher, GTK_IS_WINDOW(root) ? GTK_WINDOW(root) : NULL, NULL, NULL, NULL);
    g_object_unref(launcher);
}

AdwNavigationPage *gaudit_environ_page_new(void)
{
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());
    gaudit_verdict verdict = gaudit_environ_verdict();

    AdwPreferencesGroup *intro = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_description(intro,
        _("The program was started with these settings, environment variables that make "
          "programs load code or modules from the places they name. It started itself again "
          "without them before it opened, so they are not in use now. Code they pointed to may "
          "have run before that, so what matters is who can change what they point to."));
    adw_preferences_page_add(page, intro);

    GString *names = g_string_new(NULL);
    size_t n = gaudit_environ_removed_count();
    for (size_t i = 0; i < n; i++) {
        char name[128];
        const char *value;
        split(gaudit_environ_removed_entry(i), name, sizeof name, &value);
        AdwPreferencesGroup *group = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(group, name);
        adw_preferences_group_set_description(group, what_it_does(name));
        if (plain_name(name)) {
            /* Only plain names go into the command below. */
            if (names->len > 0)
                g_string_append_c(names, '|');
            g_string_append(names, name);
        }
        if (gaudit_environ_kind(name) == GAUDIT_ENV_OTHER) {
            adw_preferences_group_add(group, GTK_WIDGET(row_new(GAUDIT_VERDICT_OK,
                value[0] != '\0' ? value : _("(empty)"), _("Loads no code of its own"))));
        } else {
            g_auto(GStrv) p = parts(name, value);
            for (guint k = 0; p[k] != NULL; k++) {
                if (p[k][0] == '\0' && strcmp(name, "LD_PRELOAD") == 0)
                    continue;
                gaudit_env_judgement j;
                judge_part(name, p[k], &j);
                g_autofree char *who = gaudit_environ_kind(name) == GAUDIT_ENV_MODULES
                                               && strchr(p[k], '/') == NULL
                                           ? g_strdup(_("Taken from the system's folders"))
                                           : reach_text(&j);
                adw_preferences_group_add(group, GTK_WIDGET(row_new(
                    j.reach == GAUDIT_ENV_ROOT_ONLY ? GAUDIT_VERDICT_OK : GAUDIT_VERDICT_WARNING,
                    p[k][0] != '\0' ? p[k] : _("(empty)"), who)));
            }
        }
        adw_preferences_page_add(page, group);
    }

    /* What the user can do. */
    AdwPreferencesGroup *todo = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(todo, _("What You Can Do"));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    const char *where =
        _("Such settings are usually made in a file that is read when you log in or open a "
          "terminal. Started from a terminal, the program gets the terminal's settings; started "
          "from the menu, only those of the login. This shows the lines that set them:");
    GtkWidget *label = gtk_label_new(where);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_box_append(GTK_BOX(box), label);
    if (names->len > 0) {
        g_autofree char *cmd = g_strdup_printf(
            "grep -n -E '%s' ~/.bashrc ~/.profile ~/.bash_profile ~/.config/environment.d/*.conf "
            "/etc/environment /etc/profile.d/*.sh 2>/dev/null", names->str);
        gtk_box_append(GTK_BOX(box), gaudit_command_field_new(cmd));
    }
    const char *advice =
        verdict == GAUDIT_VERDICT_WARNING
        ? _("If you set it yourself, or a guide for another program asked you to (NVIDIA's CUDA "
            "asks for LD_LIBRARY_PATH), let it point only to folders the administrator owns and "
            "only the administrator can change. If you did not set it and cannot find where it "
            "comes from, find out before you change anything: something on your account may "
            "have set it. Checking the computer from a USB stick you start it from is then the "
            "way to be sure.")
        : _("They point only to folders the administrator controls, so nothing on your account "
            "can have put code there. You can leave them as they are: the program starts itself "
            "without them all the same.");
    GtkWidget *advice_label = gtk_label_new(advice);
    gtk_label_set_wrap(GTK_LABEL(advice_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(advice_label), 0);
    gtk_box_append(GTK_BOX(box), advice_label);
    adw_preferences_group_add(todo, box);
    /* How to write it in each kind of file: the shells' own business, so on
     * the wiki, not in the program. A fixed address, opened on a click. */
    AdwActionRow *link = ADW_ACTION_ROW(adw_action_row_new());
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(link), _("How to Change Them, File by File"));
    adw_action_row_set_subtitle(link, _("On the program's wiki, in your browser"));
    GtkWidget *link_icon = gtk_image_new_from_icon_name("gaudit-external-link-symbolic");
    gtk_accessible_update_property(GTK_ACCESSIBLE(link_icon), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   _("Opens in your browser"), -1);
    adw_action_row_add_suffix(link, link_icon);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(link), TRUE);
    g_signal_connect(link, "activated", G_CALLBACK(on_wiki), NULL);
    adw_preferences_group_add(todo, GTK_WIDGET(link));
    adw_preferences_page_add(page, todo);
    g_string_free(names, TRUE);

    return gaudit_page_wrap(GTK_WIDGET(page), _("Settings That Load Code"), "environ");
}
