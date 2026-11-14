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
    return kind == 1 || kind == 2 || kind == 3;
}

/* Text that may go into a command as it is: sent unchanged, valid UTF-8,
 * and no quote that would end the shell's quoting. */
static gboolean plain(const char *text, int exact)
{
    return exact && g_utf8_validate(text, -1, NULL) && strchr(text, '\'') == NULL;
}

/* The searched area index names, from the collection's area lines. */
static gboolean find_area(GPtrArray *lines, unsigned index, gaudit_secret_area *out)
{
    for (guint i = 0; i < lines->len; i++) {
        gaudit_secret_area a;
        if (gaudit_secrets_parse_area(g_ptr_array_index(lines, i), &a) == 0
            && a.status == GAUDIT_AREA_SEARCHED && a.index == index) {
            *out = a;
            return TRUE;
        }
    }
    return FALSE;
}

/* The command comes from this fixed table and the collected data, never
 * from the report: a rule can name a fix, not write one. */
AdwNavigationPage *gaudit_private_files_fix_page(const char *fix_id, GPtrArray *lines, guint item)
{
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    gaudit_secret_area area;
    if (fix_id == NULL || lines == NULL || item >= lines->len
        || gaudit_secrets_parse_line(g_ptr_array_index(lines, item), &f, &s) != 1
        || f.reach < GAUDIT_SECRET_GROUP || !find_area(lines, f.area, &area))
        return NULL;
    gboolean home = f.area == 0 && strcmp(f.path, ".") == 0;
    if ((strcmp(fix_id, "close-home") == 0) != home
        || (!home && strcmp(fix_id, "make-private") != 0))
        return NULL;  /* not a fix this finding can have */

    g_autofree char *shown_name = g_utf8_make_valid(f.path, -1);
    g_autofree char *shown_root = g_utf8_make_valid(area.path, -1);
    g_autofree char *shown = f.area == 0 ? g_strdup_printf("~/%s", shown_name)
                                         : g_strdup_printf("%s/%s", shown_root, shown_name);
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
    } else if (!plain(f.path, f.exact) || (f.area > 0 && !plain(area.path, area.exact))) {
        how = P_("Its name has characters that cannot be shown exactly here, so no command is "
                 "given. In the file manager, open its properties and let only you read it.");
    } else {
        how = P_("Run this command in a terminal. Afterwards only you can read it; it stays where "
                 "it is.");
        command = f.area == 0 ? g_strdup_printf("chmod go-rwx -- ~/'%s'", f.path)
                              : g_strdup_printf("chmod go-rwx -- '%s/%s'", area.path, f.path);
        note = area.remote
            ? P_("It is on a network folder: the server decides who can read it, so this may not "
                 "be enough. Check it on the server too.")
            : P_("If you no longer need it, deleting it is safer still.");
    }
    return gaudit_fix_page_new(home ? P_("Close Your Home Folder") : P_("Make It Private"),
                               problem, how, command, note);
}
