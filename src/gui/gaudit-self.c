/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <string.h>

#include "gaudit-self.h"
#include "gaudit-task-page.h"

static gboolean is(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}

gboolean gaudit_self_not_applicable(const GauditRunResult *r)
{
#if GAUDIT_DEVELOPER_BUILD
    const gaudit_self_report *s = &r->self;
    return (is(s->manifest, "missing") || is(s->manifest, "no-key")) && s->process_problems == 0
           && s->changed == 0 && s->missing == 0 && s->extra == 0;
#else
    (void)r;
    return FALSE;  /* outside a developer build, no signed list is a finding */
#endif
}

char *gaudit_self_title(const GauditRunResult *r)
{
    const gaudit_self_report *s = &r->self;
    unsigned differ = s->changed + s->missing;
    if (differ > 0)
        return g_strdup_printf(ngettext("%u of the program's files differs from its release",
                                        "%u of the program's files differ from their release",
                                        differ),
                               differ);
    if (s->process_problems > 0)
        return g_strdup(_("The program does not run as it should"));
    if (s->extra > 0)
        return g_strdup_printf(ngettext("%u file in the program's folders is not in its list",
                                        "%u files in the program's folders are not in its list",
                                        s->extra),
                               s->extra);
    if (is(s->manifest, "bad-signature") || is(s->manifest, "bad-format"))
        return g_strdup(_("The list of the program's files is not signed with its key"));
    if (is(s->manifest, "too-old"))
        return g_strdup(_("The list of the program's files is older than one seen before"));
    if (is(s->manifest, "from-future"))
        return g_strdup(_("The list of the program's files is dated in the future"));
    if (is(s->manifest, "expired"))
        return g_strdup(_("The list of the program's files has expired"));
    if (gaudit_self_not_applicable(r))
        return g_strdup(_("The program runs as it should; its files are not checked in a "
                          "developer build"));
    if (is(s->manifest, "missing") || is(s->manifest, "no-key"))
        return g_strdup(_("The program's files could not be checked: there is no signed list"));
    return g_strdup(_("No changes found in the program's files or how it runs"));
}

static AdwActionRow *row_new(gaudit_verdict verdict, const char *title, const char *subtitle)
{
    AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
    /* Paths and names come from the system: plain text, never markup. */
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    if (subtitle != NULL && *subtitle != '\0') {
        adw_action_row_set_subtitle(row, subtitle);
        adw_action_row_set_subtitle_lines(row, 0);
    }
    adw_action_row_add_prefix(row, gaudit_verdict_icon_new(verdict));
    return row;
}

/* A row for what does not apply: neither a finding nor unknown. */
static AdwActionRow *row_not_applicable(const char *title, const char *subtitle)
{
    AdwActionRow *row = ADW_ACTION_ROW(adw_action_row_new());
    adw_preferences_row_set_use_markup(ADW_PREFERENCES_ROW(row), FALSE);
    adw_preferences_row_set_title(ADW_PREFERENCES_ROW(row), title);
    if (subtitle != NULL) {
        adw_action_row_set_subtitle(row, subtitle);
        adw_action_row_set_subtitle_lines(row, 0);
    }
    adw_action_row_add_prefix(row, gaudit_self_not_applicable_icon_new());
    return row;
}

GtkWidget *gaudit_self_not_applicable_icon_new(void)
{
    GtkWidget *icon = gtk_image_new_from_icon_name("gaudit-information-symbolic");
    gtk_widget_set_tooltip_text(icon, _("Does not apply"));
    gtk_accessible_update_property(GTK_ACCESSIBLE(icon), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   _("Does not apply"), -1);
    return icon;
}

/* The signed list: what its state means. */
static void manifest_text(const gaudit_self_report *s, gaudit_verdict *verdict, const char **title,
                          char **subtitle)
{
    *verdict = GAUDIT_VERDICT_WARNING;
    *subtitle = NULL;
    if (is(s->manifest, "ok")) {
        *verdict = GAUDIT_VERDICT_OK;
        *title = _("The list is signed with the program's key");
        /* Translators: "Version <n> · <n> files", of the signed list of the program's files. */
        *subtitle = g_strdup_printf(ngettext("Version %llu · %u file", "Version %llu · %u files",
                                             s->files),
                                    s->version, s->files);
    } else if (is(s->manifest, "bad-signature")) {
        *title = _("The list is not signed with the program's key");
        *subtitle = g_strdup(_("Its files cannot be checked against it."));
    } else if (is(s->manifest, "bad-format")) {
        *title = _("The list is signed, but could not be read");
        *subtitle = g_strdup(_("Its files cannot be checked against it."));
    } else if (is(s->manifest, "expired")) {
        *title = _("The list has expired");
        *subtitle = g_strdup(_("This copy of the program is older than its list allows. "
                               "Installing a new version brings a new list."));
    } else if (is(s->manifest, "too-old")) {
        *title = _("The list is older than one this computer has seen");
        *subtitle = g_strdup(_("An older copy of the program may have been put in place of a newer "
                               "one."));
    } else if (is(s->manifest, "from-future")) {
        *title = _("The list is dated in the future");
        *subtitle = g_strdup(_("Look at the computer's clock first. If it is right, the list "
                               "was not made when the program was released."));
    } else if (is(s->manifest, "missing")) {
        *verdict = GAUDIT_VERDICT_UNKNOWN;
        *title = _("There is no signed list");
        *subtitle = g_strdup(_("The program's files cannot be checked. A copy built by others "
                               "than the program's own release, such as a distribution's "
                               "package, has no such list."));
    } else {
        *verdict = GAUDIT_VERDICT_UNKNOWN;
        *title = _("This build has no key to check with");
        *subtitle = g_strdup(_("A build for development: the program's files are not checked."));
    }
}

static const char *file_problem(const char *problem)
{
    return is(problem, "changed") ? _("Differs from the released file")
         : is(problem, "missing") ? _("Missing")
         : _("In the program's folders, but not in the list");
}

static const char *process_name(const char *which)
{
    return is(which, "gui") ? _("The program's window") : _("The program's background process");
}

static const char *process_problem(const char *problem)
{
    return is(problem, "exe") ? _("Runs another program than its own")
         : is(problem, "env") ? _("Started with a setting that loads other code")
         : is(problem, "maps") ? _("Runs code from outside the system's folders, or from a file "
                                   "others than the administrator can change")
         : _("Had ended before it could be checked");
}

AdwNavigationPage *gaudit_self_page_new(const GauditRunResult *r, const char *when)
{
    const gaudit_self_report *s = &r->self;
    gaudit_verdict verdict = gaudit_self_verdict(s);
    AdwPreferencesPage *page = ADW_PREFERENCES_PAGE(adw_preferences_page_new());

    /* What was checked, and when. */
    AdwPreferencesGroup *intro = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    g_autofree char *title = gaudit_self_title(r);
    /* Translators: "<what was found> · checked at <time>". */
    g_autofree char *found = g_strdup_printf(_("%s · checked at %s"), title, when);
    gboolean na = gaudit_self_not_applicable(r);
    adw_preferences_group_add(intro, GTK_WIDGET(na ? row_not_applicable(found, NULL)
                                                   : row_new(verdict, found, NULL)));
    adw_preferences_group_set_description(intro, na
        ? _("The program checks that it runs its own programs, without settings or code that do "
            "not belong to it. In a released version it also compares its own files with the "
            "list signed at the release; a developer build has no such list, so that part is "
            "left out. This is done with administrator rights, by the part of the program the "
            "rest of it cannot change.")
        : _("The program compares its own files with the list signed when it was released, and "
            "checks that it runs its own programs, without settings or code that do not belong "
            "to it. This is done with administrator rights, by the part of the program the rest "
            "of it cannot change."));
    adw_preferences_page_add(page, intro);

    /* The signed list. */
    AdwPreferencesGroup *list = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(list, _("Signed List of Files"));
    gaudit_verdict mv;
    const char *mt;
    g_autofree char *ms = NULL;
    manifest_text(s, &mv, &mt, &ms);
    if (na)
        adw_preferences_group_add(list, GTK_WIDGET(row_not_applicable(
            _("Not checked in a developer build"),
            _("A build for development: the program's files are not checked."))));
    else
        adw_preferences_group_add(list, GTK_WIDGET(row_new(mv, mt, ms)));
    adw_preferences_page_add(page, list);

    /* Files that differ, are missing or are not listed. */
    if (r->n_self_files > 0) {
        AdwPreferencesGroup *files = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(files, _("Files"));
        unsigned all = s->changed + s->missing + s->extra;
        if (all > r->n_self_files) {
            unsigned more = all - r->n_self_files;
            g_autofree char *d = g_strdup_printf(ngettext("%u more is not listed here.",
                                                          "%u more are not listed here.", more),
                                                 more);
            adw_preferences_group_set_description(files, d);
        }
        for (unsigned i = 0; i < r->n_self_files; i++)
            adw_preferences_group_add(files, GTK_WIDGET(row_new(GAUDIT_VERDICT_WARNING,
                r->self_files[i].path, file_problem(r->self_files[i].problem))));
        adw_preferences_page_add(page, files);
    }

    /* The processes that asked for the check. */
    if (s->processes > 0) {
        AdwPreferencesGroup *procs = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
        adw_preferences_group_set_title(procs, _("How the Program Runs"));
        if (s->process_problems > r->n_self_processes) {
            unsigned more = s->process_problems - r->n_self_processes;
            g_autofree char *d = g_strdup_printf(ngettext("%u more is not listed here.",
                                                          "%u more are not listed here.", more),
                                                 more);
            adw_preferences_group_set_description(procs, d);
        }
        if (s->process_problems == 0)
            adw_preferences_group_add(procs, GTK_WIDGET(row_new(GAUDIT_VERDICT_OK,
                _("The program's window and background process run as they should"), NULL)));
        for (unsigned i = 0; i < r->n_self_processes; i++) {
            const gaudit_self_process *p = &r->self_processes[i];
            /* Translators: "<part of the program>: <what is wrong>", e.g.
             * "The program's window: Started with a setting that loads other code". */
            g_autofree char *t = g_strdup_printf(_("%s: %s"), process_name(p->which),
                                                 process_problem(p->problem));
            adw_preferences_group_add(procs, GTK_WIDGET(row_new(GAUDIT_VERDICT_WARNING, t, p->detail)));
        }
        adw_preferences_page_add(page, procs);
    }

    /* What it means: said plainly, never as a level of danger. */
    AdwPreferencesGroup *meaning = ADW_PREFERENCES_GROUP(adw_preferences_group_new());
    adw_preferences_group_set_title(meaning, _("What It Means"));
    const char *text =
        verdict == GAUDIT_VERDICT_WARNING
        ? _("Something that differs is not proof that someone has changed the program: a file "
            "changed by hand, or a version installed outside the package system, gives the "
            "same result. But while it is so, its results cannot be relied on. To be sure, "
            "check the computer from a USB stick you start it from, and install the program "
            "again from its package.")
        : verdict == GAUDIT_VERDICT_OK
        ? _("No signs of change were found. That is not a promise that the computer is clean: "
            "someone who has taken over the administrator account can hide more than the "
            "program can see.")
        : na
        ? _("A build for development runs from where it was built, so there is nothing to "
            "compare its files with. How it runs is checked all the same.")
        : _("Without a signed list, the program can check how it runs, but not whether its "
            "files are the ones it was released with.");
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    adw_preferences_group_add(meaning, label);
    adw_preferences_page_add(page, meaning);

    return gaudit_page_wrap(GTK_WIDGET(page), _("The Program's Self-Check"), "self");
}
