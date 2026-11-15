/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "gaudit-private-files.h"
#include "gaudit-task-page.h"
#include "gaudit-report-run.h"
#include "gaudit-orchestrator.h"
#include "secrets.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_PRIVATE_FILES_DOMAIN, s)

gboolean gaudit_private_files_line(const char *line, gboolean *last)
{
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    int kind = gaudit_secrets_parse_line(line, &f, &s);
    *last = kind == 2;
    return kind >= 1 && kind <= 5;
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

/* --- Checking a finding again after a fix --------------------------------
 *
 * One small collection for that one finding, by the same rules, then its
 * line in the cache is replaced (or removed when it is gone or no longer a
 * secret), the summary's counts follow, and a (rechecked ...) line says
 * so; the report is then made again from the cache. Never a guess from
 * what the fix should have done. */

typedef struct {
    GPtrArray *lines;   /* the cached collection the fix page was made from */
    guint item;
    char *line;         /* the new line, or NULL when gone */
    gboolean have;
} Recheck;

static void recheck_free(gpointer p)
{
    Recheck *r = p;
    g_ptr_array_unref(r->lines);
    g_free(r->line);
    g_free(r);
}

static gboolean on_recheck_line(const char *line, gpointer user_data)
{
    Recheck *r = user_data;
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    int kind = gaudit_secrets_parse_line(line, &f, &s);
    if (r->have || (kind != 1 && kind != 7))
        return FALSE;
    r->have = TRUE;
    r->line = kind == 1 ? g_strdup(line) : NULL;
    return TRUE;
}

static int reach_of_line(const char *line, gboolean *found)
{
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    *found = line != NULL && gaudit_secrets_parse_line(line, &f, &s) == 1;
    return *found ? (int)f.reach : -1;
}

/* A copy of lines with item replaced (or removed), the summary's counts
 * following, and the rechecked line counted up. NULL if the lines are not
 * what they should be. */
static GPtrArray *patched(GPtrArray *lines, guint item, const char *line)
{
    gboolean old_found, new_found;
    int old_reach = reach_of_line(g_ptr_array_index(lines, item), &old_found);
    int new_reach = reach_of_line(line, &new_found);
    if (!old_found)
        return NULL;
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *when = g_date_time_format(now, "%H:%M");
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    unsigned rechecked = 1;
    gboolean summary_seen = FALSE;
    for (guint i = 0; i < lines->len; i++) {
        const char *l = g_ptr_array_index(lines, i);
        gaudit_secret_finding f;
        gaudit_secrets_summary s;
        int kind = gaudit_secrets_parse_line(l, &f, &s);
        if (i == item) {
            if (line != NULL)
                g_ptr_array_add(out, g_strdup(line));
            continue;
        }
        if (kind == 6) {
            unsigned n;
            if (sscanf(l, "(rechecked (count %u)", &n) == 1)
                rechecked = n + 1;
            continue;  /* written again below, before the summary */
        }
        if (kind == 2) {
            /* The counts follow the finding's new state. */
            if (old_reach == GAUDIT_SECRET_OTHERS) s.others--;
            if (old_reach == GAUDIT_SECRET_GROUP) s.groups--;
            if (new_reach == GAUDIT_SECRET_OTHERS) s.others++;
            if (new_reach == GAUDIT_SECRET_GROUP) s.groups++;
            if (!new_found) {
                s.count--;
                s.shown--;
            }
            char buf[256], again[128];
            snprintf(again, sizeof again, "(rechecked (count %u) (when \"%s\"))", rechecked,
                     when != NULL ? when : "");
            g_ptr_array_add(out, g_strdup(again));
            if (gaudit_secrets_format_summary(&s, buf, sizeof buf) != 0) {
                g_ptr_array_unref(out);
                return NULL;
            }
            buf[strcspn(buf, "\n")] = '\0';
            g_ptr_array_add(out, g_strdup(buf));
            summary_seen = TRUE;
            continue;
        }
        g_ptr_array_add(out, g_strdup(l));
    }
    if (!summary_seen) {
        g_ptr_array_unref(out);
        return NULL;
    }
    return out;
}

static void on_recheck_done(gboolean broken, gpointer user_data)
{
    Recheck *r = user_data;
    const GauditTaskInfo *task = gaudit_task_by_id("core.private-files");
    /* Only the collection the page was made from: a newer one has seen it. */
    if (!broken && r->have && task != NULL && gaudit_cache_lines(task, NULL) == r->lines) {
        g_autoptr(GPtrArray) next = patched(r->lines, r->item, r->line);
        if (next != NULL) {
            g_autofree char *command = g_strdup(gaudit_cache_command(task));
            gaudit_cache_store(task, command, next, gaudit_cache_full(task));
            gaudit_cache_changed(task);
        }
    }
    recheck_free(r);
}

/* After the fix: the finding at item checked again. data: a Recheck to start. */
static void on_fixed(gpointer data)
{
    Recheck *proto = data;
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    gaudit_secret_area area;
    if (gaudit_secrets_parse_line(g_ptr_array_index(proto->lines, proto->item), &f, &s) != 1
        || !find_area(proto->lines, f.area, &area))
        return;
    Recheck *r = g_new0(Recheck, 1);
    r->lines = g_ptr_array_ref(proto->lines);
    r->item = proto->item;
    g_autofree char *index = g_strdup_printf("%u", f.area);
    const char *args[] = { "secrets", "item", index, area.path, f.path, NULL };
    gaudit_orchestrator_start(args, 30, FALSE, on_recheck_line, on_recheck_done, r);
}

static Recheck *recheck_new(GPtrArray *lines, guint item)
{
    Recheck *r = g_new0(Recheck, 1);
    r->lines = g_ptr_array_ref(lines);
    r->item = item;
    return r;
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
    g_auto(GStrv) run = NULL;  /* the same fix as a fixed operation, when it has one */
    const char *how, *note = NULL;
    if (!f.owned) {
        how = P_("It belongs to another account, so only that account or the administrator can "
                 "change who may read it.");
    } else if (home) {
        how = P_("Run this command in a terminal. Others can still see the names of your files, "
                 "but no longer change them.");
        command = g_strdup("chmod go-w ~");
        run = g_strdupv((char *[]){ (char *)"fix", (char *)"close-home", area.path, NULL });
    } else if (!plain(f.path, f.exact) || (f.area > 0 && !plain(area.path, area.exact))) {
        how = P_("Its name has characters that cannot be shown exactly here, so no command is "
                 "given. In the file manager, open its properties and let only you read it.");
    } else {
        how = P_("Run this command in a terminal. Afterwards only you can read it; it stays where "
                 "it is.");
        command = f.area == 0 ? g_strdup_printf("chmod go-rwx -- ~/'%s'", f.path)
                              : g_strdup_printf("chmod go-rwx -- '%s/%s'", area.path, f.path);
        run = g_strdupv((char *[]){ (char *)"fix", (char *)"make-private", area.path, f.path, NULL });
        note = area.remote
            ? P_("It is on a network folder: the server decides who can read it, so this may not "
                 "be enough. Check it on the server too.")
            /* Never advice to delete: tighten the access, and check it took. */
            : P_("Afterwards, check again: it should then be listed under the files only you can read.");
    }
    return gaudit_fix_page_new(home ? P_("Close Your Home Folder") : P_("Make It Private"),
                               problem, how, command, note, (const char *const *)run,
                               on_fixed, recheck_new(lines, item), recheck_free);
}
