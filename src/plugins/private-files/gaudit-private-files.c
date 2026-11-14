/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "gaudit-private-files.h"
#include "gaudit-task-page.h"
#include "secrets.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_PRIVATE_FILES_DOMAIN, s)

gboolean gaudit_private_files_line(const char *line, gboolean *last)
{
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    int kind = gaudit_secrets_parse_line(line, &f, &s);
    *last = kind == 2;
    return kind == 1 || kind == 2;
}

/* A path that may go into a command as it is: sent unchanged, valid
 * UTF-8, and no quote that would end the shell's quoting. */
static gboolean plain_path(const gaudit_secret_finding *f)
{
    return f->exact && g_utf8_validate(f->path, -1, NULL) && strchr(f->path, '\'') == NULL;
}

/* The command comes from this fixed table and the collected data, never
 * from the report: a rule can name a fix, not write one. */
AdwNavigationPage *gaudit_private_files_fix_page(const char *fix_id, const char *item_line)
{
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    if (fix_id == NULL || gaudit_secrets_parse_line(item_line, &f, &s) != 1
        || f.reach < GAUDIT_SECRET_GROUP)
        return NULL;
    gboolean home = strcmp(f.path, ".") == 0;
    if ((strcmp(fix_id, "close-home") == 0) != home
        || (!home && strcmp(fix_id, "make-private") != 0))
        return NULL;  /* not a fix this finding can have */

    g_autofree char *shown_name = g_utf8_make_valid(f.path, -1);
    g_autofree char *shown = g_strdup_printf("~/%s", shown_name);
    g_autofree char *problem = home
        ? g_strdup(P_("Others can change what is in your home folder."))
        : f.reach == GAUDIT_SECRET_OTHERS
        /* Translators: %s is a file name, e.g. "~/.netrc". */
        ? g_strdup_printf(P_("Every account on this computer can read %s."), shown)
        : g_strdup_printf(P_("Members of a group can read %s."), shown);
    g_autofree char *command = NULL;
    const char *how, *note = NULL;
    if (!f.owned) {
        how = P_("It belongs to another account, so only that account or the administrator can "
                 "change who may read it.");
    } else if (home) {
        how = P_("Run this command in a terminal. Others can still see the names of your files, "
                 "but no longer change them.");
        command = g_strdup("chmod go-w ~");
    } else if (!plain_path(&f)) {
        how = P_("Its name has characters that cannot be shown exactly here, so no command is "
                 "given. In the file manager, open its properties and let only you read it.");
    } else {
        how = P_("Run this command in a terminal. Afterwards only you can read it; it stays where "
                 "it is.");
        command = g_strdup_printf("chmod go-rwx -- ~/'%s'", f.path);
        note = P_("If you no longer need it, deleting it is safer still.");
    }
    return gaudit_fix_page_new(home ? P_("Close Your Home Folder") : P_("Make It Private"),
                               problem, how, command, note);
}
