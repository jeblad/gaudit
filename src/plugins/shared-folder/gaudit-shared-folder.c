/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "gaudit-orchestrator.h"
#include "gaudit-report-run.h"
#include "gaudit-session.h"
#include "gaudit-shared-folder.h"
#include "gaudit-task-page.h"
#include "gaudit-task.h"
#include "shared-folder.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_SHARED_FOLDER_DOMAIN, s)
#define PN_(one, many, n) g_dngettext(GAUDIT_SHARED_FOLDER_DOMAIN, one, many, n)

gboolean gaudit_shared_folder_line(const char *line, gboolean *last)
{
    int kind = gaudit_shared_parse_line(line, NULL, NULL, NULL, NULL);
    *last = kind == GAUDIT_SHARED_LINE_END;
    return kind > 0 || gaudit_shared_parse_secret(line, NULL) == 0
           || gaudit_shared_parse_secret_scan(line, NULL) == 0;
}

/* --- After a change: the collection again ---------------------------------- */

static void on_recollected(gaudit_run_status status, const GauditRunResult *result, gpointer data)
{
    (void)status;
    (void)result;
    (void)data;
}

static void recollect(void)
{
    const GauditTaskInfo *task = gaudit_task_by_id("core.shared-folder");
    if (task != NULL)
        gaudit_session_run(gaudit_task_home_command(task, GAUDIT_LEVEL_QUICK), NULL, on_recollected,
                           NULL);
}

/* --- The page: a sequence ----------------------------------------------------
 *
 * Each step a text and its button; under the button nothing until it is
 * pressed, then its result, and when it went well the next step under
 * that. A button whose step is over stays grey; opening the page again
 * starts anew. */

typedef struct {
    int refs;
    char from[256];      /* the duplicate, straight in the home folder */
    char to[256];        /* the folder in use, straight in the home folder */
    GtkWidget *box;      /* weak: the page's column */
    GtkWidget *last;     /* weak: what comes last in it, to add after */
    GPtrArray *clashes;  /* names in both folders, from the check */
    gaudit_shared_moves moves;
} Tidy;

static Tidy *tidy_ref(Tidy *t)
{
    t->refs++;
    return t;
}

static void tidy_unref(gpointer p)
{
    Tidy *t = p;
    if (--t->refs > 0)
        return;
    if (t->box != NULL)
        g_object_remove_weak_pointer(G_OBJECT(t->box), (gpointer *)&t->box);
    if (t->last != NULL)
        g_object_remove_weak_pointer(G_OBJECT(t->last), (gpointer *)&t->last);
    g_ptr_array_unref(t->clashes);
    g_free(t);
}

static void set_last(Tidy *t, GtkWidget *w)
{
    if (t->last != NULL)
        g_object_remove_weak_pointer(G_OBJECT(t->last), (gpointer *)&t->last);
    t->last = w;
    g_object_add_weak_pointer(G_OBJECT(w), (gpointer *)&t->last);
}

/* Adds w at the end of the sequence. */
static void append(Tidy *t, GtkWidget *w)
{
    if (t->box == NULL || t->last == NULL)
        return;
    gtk_box_insert_child_after(GTK_BOX(t->box), w, t->last);
    set_last(t, w);
}

static void say(Tidy *t, const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    append(t, l);
}

static GtkWidget *step_button(Tidy *t, const char *label, GCallback cb)
{
    GtkWidget *b = gaudit_action_button_new(label, FALSE, TRUE);
    gtk_widget_set_halign(b, GTK_ALIGN_END);
    g_signal_connect_data(b, "clicked", cb, tidy_ref(t), (GClosureNotify)(void (*)(void))tidy_unref, 0);
    append(t, b);
    return b;
}

typedef struct {
    Tidy *t;
    gboolean got;
} Run;

static gboolean on_tidy_line(const char *line, gpointer user_data)
{
    Run *r = user_data;
    char clash[256];
    gaudit_shared_moves m;
    int kind = gaudit_shared_parse_tidy(line, clash, sizeof clash, &m);
    if (kind == 1 && !r->got) {
        if (r->t->clashes->len < 16)
            g_ptr_array_add(r->t->clashes, g_strdup(clash));
        return TRUE;
    }
    if ((kind == 2 || kind == 3) && !r->got) {
        r->got = TRUE;
        r->t->moves = m;
        return TRUE;
    }
    return FALSE;
}

static void start(Tidy *t, const char *const *args, GauditOrchestratorDoneFn done)
{
    Run *r = g_new0(Run, 1);
    r->t = tidy_ref(t);
    g_ptr_array_set_size(t->clashes, 0);
    memset(&t->moves, 0, sizeof t->moves);
    gaudit_orchestrator_start(args, 60, FALSE, on_tidy_line, done, r);
}

static void finish_run(Run *r)
{
    tidy_unref(r->t);
    g_free(r);
}

static void on_remove_clicked(GtkButton *button, gpointer user_data);

static void on_removed(gboolean broken, gpointer user_data)
{
    Run *r = user_data;
    Tidy *t = r->t;
    if (broken || !r->got)
        say(t, P_("It could not be done."));
    else if (t->moves.result == 0) {
        /* Translators: %s is a folder, e.g. "~/Public". */
        g_autofree char *text = g_strdup_printf(P_("Done: ~/%s is gone, and ~/%s is the one "
                                                   "folder for what you share."), t->from, t->to);
        say(t, text);
        recollect();
    } else if (t->moves.result == 1) {
        say(t, P_("It is not empty, so it was left as it is. Look in it yourself; the program "
                  "never deletes files."));
    } else {
        say(t, P_("It was not removed: it is not one of the folders the program tidies, or "
                  "something now shares it."));
    }
    finish_run(r);
}

static void offer_remove(Tidy *t)
{
    /* Translators: %s is a folder, e.g. "Public". */
    g_autofree char *text = g_strdup_printf(P_("~/%s is empty now. Removing it leaves one folder "
                                               "for what you share. Only an empty folder can be "
                                               "removed this way."), t->from);
    say(t, text);
    step_button(t, P_("Remove the Empty Folder"), G_CALLBACK(on_remove_clicked));
}

static void on_remove_clicked(GtkButton *button, gpointer user_data)
{
    Tidy *t = user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    const char *args[] = { "shared", "remove", t->from, NULL };
    start(t, args, on_removed);
}

static void on_merged(gboolean broken, gpointer user_data)
{
    Run *r = user_data;
    Tidy *t = r->t;
    if (broken || !r->got || t->moves.result == 2) {
        say(t, P_("Nothing was moved: it is not one of the folders the program tidies, or "
                  "something now shares one of them."));
    } else if (t->moves.result == 0) {
        /* Translators: a count, then a folder. */
        g_autofree char *text = g_strdup_printf(
            PN_("Moved %u item into ~/%s.", "Moved %u items into ~/%s.", t->moves.moved),
            t->moves.moved, t->to);
        say(t, text);
        offer_remove(t);
    } else {
        say(t, P_("Something came in the way after the check, so it stopped. What was moved "
                  "is in the folder in use; open this page again to see what is left."));
    }
    finish_run(r);
}

static void on_merge_clicked(GtkButton *button, gpointer user_data)
{
    Tidy *t = user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    const char *args[] = { "shared", "merge", t->from, t->to, NULL };
    start(t, args, on_merged);
}

static void on_checked(gboolean broken, gpointer user_data)
{
    Run *r = user_data;
    Tidy *t = r->t;
    const gaudit_shared_moves *m = &t->moves;
    if (broken || !r->got || m->result == 2) {
        say(t, P_("It could not be checked: it is not one of the folders the program tidies, or "
                  "something now shares one of them."));
    } else if (m->result == 0) {
        /* Translators: a count, then two folders. */
        g_autofree char *text = g_strdup_printf(
            PN_("%u item can be moved from ~/%s into ~/%s. Nothing there has the same name, so "
                "nothing is replaced.",
                "%u items can be moved from ~/%s into ~/%s. Nothing there has the same name, so "
                "nothing is replaced.", m->moved),
            m->moved, t->from, t->to);
        say(t, text);
        /* Translators: %s is a folder, e.g. "Offentlig". */
        g_autofree char *label = g_strdup_printf(P_("Move Into ~/%s"), t->to);
        step_button(t, label, G_CALLBACK(on_merge_clicked));
    } else {
        GString *text = g_string_new(NULL);
        if (m->clashes > 0) {
            g_autofree char *names = NULL;
            g_ptr_array_add(t->clashes, NULL);
            names = g_strjoinv(", ", (char **)t->clashes->pdata);
            g_ptr_array_set_size(t->clashes, t->clashes->len - 1);
            /* Translators: two folders, then a list of names. */
            g_string_append_printf(text, P_("These have the same name in ~/%s and ~/%s: %s. "
                                            "Rename one of each yourself, or move it elsewhere, "
                                            "then open this page again."),
                                   t->from, t->to, names);
        }
        if (m->other_disk > 0) {
            if (text->len > 0)
                g_string_append(text, " ");
            g_string_append(text, P_("Some of it is on another disk, so it would have to be "
                                     "copied; the program only moves."));
        }
        if (m->failed > 0) {
            if (text->len > 0)
                g_string_append(text, " ");
            g_string_append(text, P_("Some of it could not be looked at."));
        }
        if (text->len > 0)
            g_string_append(text, " ");
        g_string_append(text, P_("Nothing has been moved."));
        say(t, text->str);
        g_string_free(text, TRUE);
    }
    finish_run(r);
}

static void on_check_clicked(GtkButton *button, gpointer user_data)
{
    Tidy *t = user_data;
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    const char *args[] = { "shared", "check", t->from, t->to, NULL };
    start(t, args, on_checked);
}

/* --- The fix page -------------------------------------------------------------- */

static gboolean within(const char *path, const char *folder)
{
    size_t n = strlen(folder);
    return n > 0 && strncmp(path, folder, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/* --- A secret in a folder for sharing --------------------------------------
 *
 * One page per file. The rule decides whether a service shares it; the
 * page says what that means and what the user can do. Nothing is moved. */

static AdwNavigationPage *secret_page(const char *fix_id, GPtrArray *lines, guint item)
{
    gaudit_shared_secret sec;
    if (lines == NULL || item >= lines->len
        || gaudit_shared_parse_secret(g_ptr_array_index(lines, item), &sec) != 0)
        return NULL;
    gboolean shared = strcmp(fix_id, "secret-shared") == 0;
    /* Translators: %s is a file, e.g. "~/Public/id_rsa". */
    g_autofree char *what = g_strdup_printf(
        shared ? P_("%s looks like a key, a password or a stored login, and it is in a folder "
                    "that is shared on the local network: others on the same network may fetch "
                    "it, at home or on a café's Wi-Fi.")
               : P_("%s looks like a key, a password or a stored login, and it is in a folder "
                    "for sharing, the place for what is to be shared with others on the local "
                    "network. Nothing shares it now, but a sharing service switched on later "
                    "would."),
        sec.path);
    const char *how = P_("Move it into a folder of your own, outside the folders for sharing, in "
                         "the file manager. The program moves nothing itself.");
    const char *note =
        shared ? P_("Whether someone has fetched it already cannot be seen from here. Where the "
                    "file holds a key or a password, replacing it, with a new key or a changed "
                    "password, is the way to be sure.")
               : NULL;
    return gaudit_fix_page_new(P_("A Secret in a Folder for Sharing"), what, how, NULL, note,
                               NULL, NULL, NULL, NULL);
}

AdwNavigationPage *gaudit_shared_folder_fix_page(const char *fix_id, GPtrArray *lines, guint item)
{
    if (fix_id != NULL
        && (strcmp(fix_id, "secret-shared") == 0 || strcmp(fix_id, "secret-public") == 0))
        return secret_page(fix_id, lines, item);
    gaudit_shared_folder f;
    if (fix_id == NULL || strcmp(fix_id, "tidy") != 0 || lines == NULL || item >= lines->len
        || gaudit_shared_parse_line(g_ptr_array_index(lines, item), NULL, &f, NULL, NULL)
               != GAUDIT_SHARED_LINE_FOLDER
        || f.standard)
        return NULL;
    gaudit_shared_config c = { 0 };
    GPtrArray *services = g_ptr_array_new_with_free_func(g_free);
    for (guint i = 0; i < lines->len; i++) {
        gaudit_shared_service s;
        int kind = gaudit_shared_parse_line(g_ptr_array_index(lines, i), &c, NULL, &s, NULL);
        if (kind == GAUDIT_SHARED_LINE_SERVICE)
            g_ptr_array_add(services, g_memdup2(&s, sizeof s));
    }
    const char *home = g_get_home_dir();
    g_autofree char *from_path = g_build_filename(home, f.name, NULL);
    /* The folder in use, when it is straight in the home folder. */
    const char *to = c.state == 1 && c.exists && strncmp(c.standard, "~/", 2) == 0
                     && strchr(c.standard + 2, '/') == NULL ? c.standard + 2 : NULL;
    g_autofree char *to_path = to != NULL ? g_build_filename(home, to, NULL) : NULL;
    GString *sharers = g_string_new(NULL);
    for (guint i = 0; i < services->len; i++) {
        const gaudit_shared_service *s = g_ptr_array_index(services, i);
        if (within(from_path, s->path) || within(s->path, from_path)
            || (to_path != NULL && (within(to_path, s->path) || within(s->path, to_path))))
            g_string_append_printf(sharers, "%s%s", sharers->len > 0 ? ", " : "", s->name);
    }
    g_ptr_array_unref(services);

    g_autofree char *name = g_utf8_make_valid(f.name, -1);
    g_autofree char *problem = to != NULL
        /* Translators: two folders, e.g. "~/Public" and "~/Offentlig". */
        ? g_strdup_printf(P_("~/%s looks like the shared folder, but the one in use is ~/%s."),
                          name, to)
        : g_strdup_printf(P_("~/%s looks like the shared folder."), name);
    const char *how;
    gboolean offer = FALSE;
    if (f.entries == -2) {
        how = P_("It is on another disk or a network folder, so it is not looked in here, and "
                 "nothing is moved into or out of it. Whether to keep it is up to you.");
    } else if (f.link) {
        how = P_("It is a link, not a folder of its own, so there is nothing to tidy here. "
                 "Whether to keep it is up to you.");
    } else if (sharers->len > 0) {
        how = P_("Something shares one of the two folders, so nothing is moved or removed "
                 "here: that would change what is shared without you seeing it. Decide first "
                 "whether the sharing is meant.");
    } else if (to == NULL) {
        how = P_("No folder for sharing is set up in your user folder settings, so there is "
                 "nothing to tidy it into.");
    } else {
        how = P_("Two folders for the same thing make it unclear which one is shared. The "
                 "program can move what is in it into the folder in use, never replacing "
                 "anything, and then remove it once it is empty. It never deletes files.");
        offer = TRUE;
    }
    g_autofree char *note = sharers->len > 0
        /* Translators: %s is a list of shares or programs. */
        ? g_strdup_printf(P_("Shared by: %s"), sharers->str)
        : NULL;
    g_string_free(sharers, TRUE);
    AdwNavigationPage *page = gaudit_fix_page_new(P_("Tidy the Shared Folder"), problem, how,
                                                  NULL, note, NULL, NULL, NULL, NULL);
    GtkWidget *box = g_object_get_data(G_OBJECT(page), "gaudit-fix-box");
    GtkWidget *anchor = g_object_get_data(G_OBJECT(page), "gaudit-fix-how");
    if (!offer || box == NULL || anchor == NULL)
        return page;
    Tidy *t = g_new0(Tidy, 1);
    t->refs = 1;
    t->clashes = g_ptr_array_new_with_free_func(g_free);
    g_strlcpy(t->from, f.name, sizeof t->from);
    g_strlcpy(t->to, to, sizeof t->to);
    t->box = box;
    g_object_add_weak_pointer(G_OBJECT(box), (gpointer *)&t->box);
    set_last(t, anchor);
    g_object_set_data_full(G_OBJECT(page), "gaudit-tidy", t, tidy_unref);
    if (f.entries == 0)
        offer_remove(t);
    else
        step_button(t, P_("Check What Can Be Moved"), G_CALLBACK(on_check_clicked));
    return page;
}
