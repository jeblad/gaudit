/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "cloud-folders.h"
#include "cloud.h"
#include "gaudit-cloud.h"
#include "gaudit-orchestrator.h"
#include "gaudit-report-run.h"
#include "gaudit-session.h"
#include "gaudit-task-page.h"
#include "gaudit-task.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_CLOUD_DOMAIN, s)
#define PN_(one, many, n) g_dngettext(GAUDIT_CLOUD_DOMAIN, one, many, n)

gboolean gaudit_cloud_line_ok(const char *line, gboolean *last)
{
    int kind = gaudit_cloud_parse_line(line, NULL, NULL);
    *last = kind == 2;
    return kind > 0 || gaudit_cloud_parse_unit(line, NULL) == 3
           || gaudit_cloud_parse_plain(line, NULL) == 0;
}

/* --- Setting up a cloud service with rclone -----------------------------------
 *
 * A sequence dialog: each step a text and its button, the next step under
 * it once it is done. The program writes nothing and never sees a token:
 * the login token goes from the browser straight to rclone in a terminal,
 * and rclone writes its own configuration (John, 2026-11-19). The program
 * only shows what to answer, and looks again to see that it took. */

/* The services the page can set up: the shared table (common/cloud.h). */
#define services gaudit_cloud_setup_services
#define N_SERVICES gaudit_cloud_setup_services_count

typedef struct {
    int refs;
    guint service;
    char remote[128];    /* the remote found after setting it up */
    gboolean encrypted;  /* an encrypted remote over it was found */
    GtkWidget *box;      /* weak */
    GtkWidget *last;     /* weak: what comes last, to add after */
    GtkWidget *dropdown; /* weak */
    guint offered[16];   /* the dropdown's entries, as indexes into the table */
    /* Those rclone reaches already, but nothing mounts at login: the
     * dropdown's entry goes straight to mounting, with what was found. */
    gboolean login_only[16];
    char found_remote[16][128], found_via[16][128];
    /* Set up already with another program (Dropbox's own). */
    char other_client[16][16];
    char via[128];       /* the crypt remote over it, found */
    /* Where its folders go, and the language of their names: chosen once,
     * when the page is made (cloud-folders.h), so what is shown and what is
     * written are the same. */
    char gathering[64];
    const gaudit_cloud_language *lang;
    /* What the user chose: the private disk, the shareable one, or both
     * (John, 2026-11-19). adding: the private one is there already, and
     * the shareable one is added beside it. */
    int model;
    gboolean adding;
    gboolean addable[16];  /* the dropdown's entries that add the shareable disk */
} Setup;

enum { MODEL_PRIVATE = 1, MODEL_SHARED = 2, MODEL_BOTH = 3 };

static Setup *setup_ref(Setup *s)
{
    s->refs++;
    return s;
}

static void setup_unref(gpointer p)
{
    Setup *s = p;
    if (--s->refs > 0)
        return;
    if (s->box != NULL)
        g_object_remove_weak_pointer(G_OBJECT(s->box), (gpointer *)&s->box);
    if (s->last != NULL)
        g_object_remove_weak_pointer(G_OBJECT(s->last), (gpointer *)&s->last);
    if (s->dropdown != NULL)
        g_object_remove_weak_pointer(G_OBJECT(s->dropdown), (gpointer *)&s->dropdown);
    g_free(s);
}

static void set_last(Setup *s, GtkWidget *w)
{
    if (s->last != NULL)
        g_object_remove_weak_pointer(G_OBJECT(s->last), (gpointer *)&s->last);
    s->last = w;
    g_object_add_weak_pointer(G_OBJECT(w), (gpointer *)&s->last);
}

static void append(Setup *s, GtkWidget *w)
{
    if (s->box == NULL || s->last == NULL)
        return;
    gtk_box_insert_child_after(GTK_BOX(s->box), w, s->last);
    set_last(s, w);
}

static void say(Setup *s, const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(l), FALSE);
    append(s, l);
}

static void command(Setup *s, const char *cmd)
{
    append(s, gaudit_command_field_new(cmd));
}

/* rclone config asks one thing at a time; what to answer, one row each, so
 * what to type stands out. ask: rclone's own prompt, shown as it is
 * (literal), or the question in words where its exact text is not known
 * here. type: what to type, NULL for Enter alone; typed: shown as it is
 * (monospace), else in words. */
typedef struct {
    const char *ask;
    gboolean literal;
    const char *type;
    gboolean typed;
    const char *note;   /* may be NULL */
} Answer;

static GtkWidget *answer_label(const char *text, gboolean literal, gboolean strong)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_use_markup(GTK_LABEL(l), FALSE);
    gtk_label_set_use_underline(GTK_LABEL(l), FALSE);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(l), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_set_valign(l, GTK_ALIGN_BASELINE_FILL);
    if (literal) {
        gtk_widget_add_css_class(l, "monospace");
        gtk_widget_set_direction(l, GTK_TEXT_DIR_LTR);
        gtk_label_set_selectable(GTK_LABEL(l), TRUE);
    }
    if (strong) {
        PangoAttrList *attrs = pango_attr_list_new();
        pango_attr_list_insert(attrs, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        gtk_label_set_attributes(GTK_LABEL(l), attrs);
        pango_attr_list_unref(attrs);
    }
    return l;
}

static void answers(Setup *s, const Answer *a, size_t n)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 18);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    GtkWidget *head_ask = answer_label(P_("rclone asks"), FALSE, FALSE);
    GtkWidget *head_type = answer_label(P_("You type"), FALSE, FALSE);
    gtk_widget_add_css_class(head_ask, "caption-heading");
    gtk_widget_add_css_class(head_type, "caption-heading");
    gtk_grid_attach(GTK_GRID(grid), head_ask, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), head_type, 1, 0, 1, 1);
    int row = 1;
    for (size_t i = 0; i < n; i++) {
        GtkWidget *ask = answer_label(a[i].ask, a[i].literal, FALSE);
        gtk_widget_set_hexpand(ask, TRUE);
        if (i > 0)
            gtk_widget_set_margin_top(ask, 8);
        gtk_grid_attach(GTK_GRID(grid), ask, 0, row, 1, 1);
        GtkWidget *type;
        if (a[i].type == NULL) {
            type = gtk_shortcut_label_new("Return");
            gtk_widget_set_halign(type, GTK_ALIGN_START);
            gtk_widget_set_valign(type, GTK_ALIGN_CENTER);
        } else {
            type = answer_label(a[i].type, a[i].typed, a[i].typed);
        }
        if (i > 0)
            gtk_widget_set_margin_top(type, 8);
        gtk_grid_attach(GTK_GRID(grid), type, 1, row, 1, 1);
        row++;
        if (a[i].note != NULL) {
            GtkWidget *note = answer_label(a[i].note, FALSE, FALSE);
            gtk_widget_add_css_class(note, "dim-label");
            gtk_widget_add_css_class(note, "caption");
            gtk_grid_attach(GTK_GRID(grid), note, 0, row, 2, 1);
            row++;
        }
    }
    /* In a card, with margins inside it. */
    GtkWidget *pad = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(pad, "card");
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);
    gtk_widget_set_margin_top(grid, 12);
    gtk_widget_set_margin_bottom(grid, 12);
    gtk_box_append(GTK_BOX(pad), grid);
    append(s, pad);
}

/* The first and last rows, the same for every setup. */
#define ANSWER_NEW \
    { "Current remotes", TRUE, "n", TRUE, \
      P_("New remote. With no remotes set up yet, rclone asks in other words; the answer is " \
         "the same.") }
#define ANSWER_KEEP_QUIT(keep) \
    { keep, TRUE, "y", TRUE, NULL }, \
    { "Current remotes", TRUE, "q", TRUE, P_("Quit config.") }

static GtkWidget *button(Setup *s, const char *label, gboolean is_default, GCallback cb)
{
    GtkWidget *b = gaudit_action_button_new(label, FALSE, is_default);
    gtk_widget_set_halign(b, GTK_ALIGN_END);
    g_signal_connect_data(b, "clicked", cb, setup_ref(s), (GClosureNotify)(void (*)(void))setup_unref, 0);
    append(s, b);
    return b;
}

/* Two buttons side by side, the default at the end. */
static void buttons(Setup *s, const char *plain, GCallback plain_cb, const char *def, GCallback def_cb)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    GtkWidget *a = gaudit_action_button_new(plain, FALSE, FALSE);
    GtkWidget *b = gaudit_action_button_new(def, FALSE, TRUE);
    g_signal_connect_data(a, "clicked", plain_cb, setup_ref(s), (GClosureNotify)(void (*)(void))setup_unref, 0);
    g_signal_connect_data(b, "clicked", def_cb, setup_ref(s), (GClosureNotify)(void (*)(void))setup_unref, 0);
    g_object_set_data(G_OBJECT(a), "gaudit-other", b);
    g_object_set_data(G_OBJECT(b), "gaudit-other", a);
    gtk_box_append(GTK_BOX(row), a);
    gtk_box_append(GTK_BOX(row), b);
    append(s, row);
}

/* Three buttons side by side, the default at the end. */
static void buttons3(Setup *s, const char *l1, GCallback c1, const char *l2, GCallback c2,
                     const char *def, GCallback def_cb)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    g_object_set_data(G_OBJECT(row), "gaudit-row", GINT_TO_POINTER(1));
    const char *labels[] = { l1, l2, def };
    GCallback cbs[] = { c1, c2, def_cb };
    for (int i = 0; i < 3; i++) {
        GtkWidget *b = gaudit_action_button_new(labels[i], FALSE, i == 2);
        g_signal_connect_data(b, "clicked", cbs[i], setup_ref(s),
                              (GClosureNotify)(void (*)(void))setup_unref, 0);
        gtk_box_append(GTK_BOX(row), b);
    }
    append(s, row);
}

/* A step is over: its button, and those beside it, go grey. */
static void done(GtkButton *b)
{
    gtk_widget_set_sensitive(GTK_WIDGET(b), FALSE);
    GtkWidget *other = g_object_get_data(G_OBJECT(b), "gaudit-other");
    if (other != NULL)
        gtk_widget_set_sensitive(other, FALSE);
    GtkWidget *row = gtk_widget_get_parent(GTK_WIDGET(b));
    if (row != NULL && g_object_get_data(G_OBJECT(row), "gaudit-row") != NULL)
        gtk_widget_set_sensitive(row, FALSE);
}

static const char *mount_remote(Setup *s, char *buf, size_t len);
static int disks_of(Setup *s, gaudit_cloud_disk disks[2]);
static void step_mount(Setup *s);
static void step_login(Setup *s);
static void step_model(Setup *s);
static void step_rclone_config(Setup *s);
static void step_token(Setup *s);
static void step_login_way(Setup *s);

/* --- Looking again ---------------------------------------------------------- */

typedef enum { LOOK_REMOTE, LOOK_CRYPT, LOOK_UNIT } Look;

static void on_remote_check(GtkButton *b, gpointer data);
static void on_crypt_check(GtkButton *b, gpointer data);
static void on_unit_check(GtkButton *b, gpointer data);

typedef struct {
    Setup *s;
    Look look;
} Again;

static void on_looked(gaudit_run_status status, const GauditRunResult *result, gpointer data)
{
    Again *a = data;
    Setup *s = a->s;
    gboolean found = FALSE, encrypted = FALSE;
    char name[128] = "";
    /* Every unit of this setup switched on and mounted. */
    gaudit_cloud_disk disks[2];
    int n = disks_of(s, disks), on = 0;
    for (int d = 0; d < n; d++) {
        char unit_file[96];
        gaudit_cloud_unit_name(&services[s->service], disks[d], unit_file, sizeof unit_file);
        for (guint i = 0; status == GAUDIT_RUN_OK && result != NULL && result->lines != NULL
                          && i < result->lines->len; i++) {
            gaudit_cloud_unit_line u;
            if (gaudit_cloud_parse_unit(g_ptr_array_index(result->lines, i), &u) == 3
                && strcmp(u.file, unit_file) == 0 && u.enabled && u.mounted) {
                on++;
                break;
            }
        }
    }
    gboolean unit_on = on == n;
    for (guint i = 0; status == GAUDIT_RUN_OK && result != NULL && result->lines != NULL
                      && i < result->lines->len; i++) {
        gaudit_cloud_line l;
        if (gaudit_cloud_parse_line(g_ptr_array_index(result->lines, i), &l, NULL) == 1
            && strcmp(l.client, "rclone") == 0 && strcmp(l.service, services[s->service].id) == 0) {
            found = TRUE;
            encrypted |= l.encrypted;
            if (name[0] == '\0')
                g_strlcpy(name, l.name, sizeof name);
            if (l.via[0] != '\0')
                g_strlcpy(s->via, l.via, sizeof s->via);
        }
    }
    if (status != GAUDIT_RUN_OK) {
        say(s, P_("The program could not look just now. Try again in a moment."));
        button(s, P_("Check Again"), TRUE,
               a->look == LOOK_REMOTE ? G_CALLBACK(on_remote_check)
               : a->look == LOOK_CRYPT ? G_CALLBACK(on_crypt_check) : G_CALLBACK(on_unit_check));
    } else if (a->look == LOOK_UNIT) {
        say(s, unit_on ? (n == 1 ? P_("Found: the service is switched on, and the folder is mounted.")
                                 : P_("Found: the services are switched on, and both folders are "
                                      "mounted."))
                       : (n == 1 ? P_("The service is not switched on and mounted yet. Run the "
                                      "commands above, then open this page again.")
                                 : P_("The services are not both switched on and mounted yet. Run "
                                      "the commands above, then open this page again.")));
    } else if (a->look == LOOK_REMOTE && found) {
        g_strlcpy(s->remote, name, sizeof s->remote);
        /* Translators: %s is the name of an rclone remote, e.g. "jotta". */
        g_autofree char *text = g_strdup_printf(P_("Found: rclone has a setup named %s."), name);
        say(s, text);
        step_model(s);
    } else if (a->look == LOOK_REMOTE) {
        say(s, P_("No such setup was found yet. Finish rclone config in the terminal, then open "
                  "this page again."));
    } else if (encrypted) {
        s->encrypted = TRUE;
        say(s, P_("Found: the files are encrypted before they leave the computer."));
        step_mount(s);
    } else {
        say(s, P_("No encrypted setup over it was found yet. Finish rclone config in the "
                  "terminal, then open this page again."));
    }
    setup_unref(s);
    g_free(a);
}

static void look_again(Setup *s, Look look);

static void on_unit_check(GtkButton *b, gpointer data)
{
    done(b);
    look_again(data, LOOK_UNIT);
}

static void look_again(Setup *s, Look look)
{
    const GauditTaskInfo *task = gaudit_task_by_id("core.cloud");
    Again *a = g_new0(Again, 1);
    a->s = setup_ref(s);
    a->look = look;
    if (task == NULL
        || !gaudit_session_run(gaudit_task_home_command(task, GAUDIT_LEVEL_QUICK), NULL, on_looked, a))
        on_looked(GAUDIT_RUN_FAILED, NULL, a);
}

/* --- Step 6: mounting ----------------------------------------------------------
 *
 * Without encryption one disk, named as the service; with it two (John,
 * 2026-11-19): the private one, the crypt remote, and the shareable one,
 * the plain remote without the encrypted folder, which also shows what
 * others share with the user. The program moves nothing between them. */

static int disks_of(Setup *s, gaudit_cloud_disk disks[2])
{
    int n = 0;
    if ((s->model & MODEL_PRIVATE) && !s->adding)
        disks[n++] = GAUDIT_CLOUD_DISK_PRIVATE;
    if (s->model & MODEL_SHARED)
        disks[n++] = GAUDIT_CLOUD_DISK_SHARED;
    return n;
}

static void folder_of(Setup *s, gaudit_cloud_disk disk, char *buf, size_t len)
{
    gaudit_cloud_folder_name(&services[s->service], disk, s->lang->private_word,
                             s->lang->shared_word, buf, len);
}

static const char *remote_of(Setup *s, gaudit_cloud_disk disk, char *buf, size_t len)
{
    if (disk == GAUDIT_CLOUD_DISK_PRIVATE)
        return mount_remote(s, buf, len);
    g_snprintf(buf, len, "%s", s->remote);
    return buf;
}

/* As a shell takes it: bare when it is only letters, digits and ._-, else
 * in single quotes (the names have none of their own). */
static gboolean shell_plain(const char *t)
{
    for (const unsigned char *c = (const unsigned char *)t; *c != '\0'; c++)
        if (!(g_ascii_isalnum(*c) || *c == '.' || *c == '_' || *c == '-' || *c == '/' || *c >= 0x80))
            return FALSE;
    return TRUE;
}

static char *shell_word(const char *t)
{
    return shell_plain(t) ? g_strdup(t) : g_shell_quote(t);
}

/* ~/<gathering>/<folder>, for a shell: each part quoted only when it
 * needs it (~/Cloud/'Dropbox (private)'), the tilde always outside. */
static char *shell_at(Setup *s, gaudit_cloud_disk disk)
{
    char folder[128];
    folder_of(s, disk, folder, sizeof folder);
    g_autofree char *g = shell_word(s->gathering);
    g_autofree char *f = shell_word(folder);
    return g_strdup_printf("~/%s/%s", g, f);
}

static void step_mount(Setup *s)
{
    gaudit_cloud_disk disks[2];
    int n = disks_of(s, disks);
    /* Translators: %s is the folder the cloud folders are gathered in, e.g. "Cloud". */
    g_autofree char *intro = g_strdup_printf(
        n == 1 ? P_("Last, make a folder for it under ~/%s, where the cloud folders are gathered, "
                    "and mount it there. Run these in a terminal:")
               : P_("Last, make two folders for it under ~/%s, where the cloud folders are "
                    "gathered, and mount one disk in each. Run these in a terminal:"),
        s->gathering);
    say(s, intro);
    for (int i = 0; i < n; i++) {
        g_autofree char *at = shell_at(s, disks[i]);
        g_autofree char *mkdir = g_strdup_printf("mkdir -p %s", at);
        command(s, mkdir);
    }
    for (int i = 0; i < n; i++) {
        char remote[160];
        remote_of(s, disks[i], remote, sizeof remote);
        g_autofree char *at = shell_at(s, disks[i]);
        g_autofree char *mount = g_strdup_printf(
            "rclone mount %s: %s --umask 077 --vfs-cache-mode full "
            "--dir-cache-time 1h%s --daemon",
            remote, at, disks[i] == GAUDIT_CLOUD_DISK_SHARED ? " --exclude '/Encrypted/**'" : "");
        command(s, mount);
    }
    say(s, P_("--vfs-cache-mode full keeps a copy of what is used on this computer, and "
              "--dir-cache-time remembers the lists of files for an hour: without them, Files "
              "fetches every file to show the folder, which can take minutes. --umask 077 shows "
              "what is there as yours "
              "alone, as it is: other accounts cannot reach a mount like this. --daemon lets it "
              "run in the background until you log out. To mount it each time you log in, "
              "rclone's own documentation shows how."));
    char priv[128], shared[128];
    folder_of(s, GAUDIT_CLOUD_DISK_PRIVATE, priv, sizeof priv);
    folder_of(s, GAUDIT_CLOUD_DISK_SHARED, shared, sizeof shared);
    if (n == 2) {
        /* Translators: the first %s is the private folder, e.g. "Dropbox (private)", the
         * second the shareable one, e.g. "Dropbox (shared folder)". */
        g_autofree char *two = g_strdup_printf(
            P_("The account is then two disks. %s is private: what you put there is encrypted "
               "before it leaves the computer, and the key is never shared. %s is shareable: "
               "the account as it was, without the encrypted folder. The provider can read what "
               "is there, it can be shared with others, and what others share with you shows "
               "there."),
            priv, shared);
        say(s, two);
    } else if (disks[0] == GAUDIT_CLOUD_DISK_SHARED) {
        /* Translators: %s is the shareable folder, e.g. "Dropbox (shared folder)". */
        g_autofree char *one = g_strdup_printf(
            P_("%s is shareable: the account as it is, without the encrypted folder. The "
               "provider can read what is there, it can be shared with others, and what others "
               "share with you shows there."),
            shared);
        say(s, one);
    } else {
        say(s, P_("Only the private disk is mounted. Files at the service from before, outside "
                  "the encrypted folder, are not shown here, and the provider can read them. "
                  "The report can look for them, when you ask."));
    }
    if (n == 2 || s->adding)
        say(s, P_("To make a file private, move it from the shareable disk to the private one "
                  "in the file manager. It is then encrypted, and deleted from the shareable "
                  "disk, though the provider may keep the deleted version for a while. The "
                  "program moves nothing itself: what was shared with you, or what others may "
                  "use, stays where it is until you move it."));
    if (s->model & MODEL_SHARED)
        say(s, P_("--exclude leaves the encrypted folder out of the shareable disk, so what "
                  "is there is not shown twice, once as unreadable names."));
    step_login(s);
}

/* --- Step 7: mounting at each login, optional --------------------------------------
 *
 * A systemd user unit per disk, written only on the user's informed choice:
 * the page shows the very text and where it goes (from common/cloud.h, the
 * same function the orchestrator writes it with), and nothing is written
 * until the button is pressed. Enabling them is the user's own command. */

static const char *mount_remote(Setup *s, char *buf, size_t len)
{
    if (s->encrypted && s->via[0] != '\0')
        g_snprintf(buf, len, "%s", s->via);
    else if (s->encrypted)
        g_snprintf(buf, len, "%s-crypt", s->remote);
    else
        g_snprintf(buf, len, "%s", s->remote);
    return buf;
}

typedef struct {
    Setup *s;
    int index;           /* which of disks_of is being written */
    gboolean written;    /* any was new */
    char result[16];
} Written;

static gboolean on_unit_line(const char *line, gpointer data)
{
    Written *w = data;
    if (w->result[0] != '\0' || sscanf(line, "(cloud-unit-written (result \"%15[a-z]\"))", w->result) != 1)
        return FALSE;
    return TRUE;
}

static void on_unit_check(GtkButton *b, gpointer data);
static void write_unit(Written *w);

static void on_unit_written(gboolean broken, gpointer data)
{
    Written *w = data;
    Setup *s = w->s;
    gaudit_cloud_disk disks[2];
    int n = disks_of(s, disks);
    if (broken || (strcmp(w->result, "written") != 0 && strcmp(w->result, "unchanged") != 0)) {
        char name[96];
        gaudit_cloud_unit_name(&services[s->service], disks[w->index], name, sizeof name);
        /* Translators: %s is a file name, e.g. "rclone-dropbox-private.service". */
        g_autofree char *text = g_strdup_printf(
            strcmp(w->result, "foreign") == 0
                ? P_("A file named %s is there already, and it is not this one, so it was left "
                     "as it is.")
                : P_("%s could not be written."),
            name);
        say(s, text);
        setup_unref(s);
        g_free(w);
        return;
    }
    w->written |= strcmp(w->result, "written") == 0;
    if (++w->index < n) {
        w->result[0] = '\0';
        write_unit(w);
        return;
    }
    say(s, w->written ? (n == 1 ? P_("Written.") : P_("Both written."))
                      : (n == 1 ? P_("It was there already, the same.")
                                : P_("They were there already, the same.")));
    say(s, n == 1 ? P_("Now stop the mount started by hand, if it runs, and switch the service "
                       "on. Run these in a terminal:")
                  : P_("Now stop the mounts started by hand, if they run, and switch the services "
                       "on. Run these in a terminal:"));
    g_autoptr(GString) units = g_string_new("systemctl --user enable --now");
    for (int i = 0; i < n; i++) {
        char name[96];
        gaudit_cloud_unit_name(&services[s->service], disks[i], name, sizeof name);
        g_string_append_printf(units, " %s", name);
        g_autofree char *at = shell_at(s, disks[i]);
        g_autofree char *stop = g_strdup_printf("fusermount -u %s", at);
        command(s, stop);
    }
    command(s, "systemctl --user daemon-reload");
    command(s, units->str);
    say(s, n == 1 ? P_("It then mounts the folder at each login, and starts it again if it stops.")
                  : P_("They then mount the folders at each login, and start them again if they "
                       "stop."));
    button(s, P_("Check"), TRUE, G_CALLBACK(on_unit_check));
    setup_unref(s);
    g_free(w);
}

static void write_unit(Written *w)
{
    Setup *s = w->s;
    gaudit_cloud_disk disks[2];
    disks_of(s, disks);
    char remote[160];
    const char *args[] = { "cloud", "unit", services[s->service].id,
                           gaudit_cloud_disk_word(disks[w->index]),
                           remote_of(s, disks[w->index], remote, sizeof remote), s->gathering,
                           s->lang->lang, NULL };
    gaudit_orchestrator_start(args, 30, FALSE, on_unit_line, on_unit_written, w);
}

static void on_write_unit(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    Written *w = g_new0(Written, 1);
    w->s = setup_ref(s);
    write_unit(w);
}

static void on_skip_unit(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    say(s, P_("Then mount it by hand after each login, with the command above. Until it is "
              "mounted, the folder is an ordinary empty folder on this computer: what is put "
              "there stays here, and is not encrypted."));
}

static void step_login(Setup *s)
{
    gaudit_cloud_disk disks[2];
    int n = disks_of(s, disks);
    char texts[2][4096], names[2][96];
    for (int i = 0; i < n; i++) {
        char remote[160], folder[128];
        folder_of(s, disks[i], folder, sizeof folder);
        if (gaudit_cloud_unit_text(&services[s->service], disks[i],
                                   remote_of(s, disks[i], remote, sizeof remote), s->gathering,
                                   folder, texts[i], sizeof texts[i]) != 0)
            return;  /* a name that may not go into a file: the user mounts by hand */
        gaudit_cloud_unit_name(&services[s->service], disks[i], names[i], sizeof names[i]);
    }
    say(s, n == 1 ? P_("Optional: mount it at each login. A mount started by hand ends when you "
                       "log out, and until it is mounted again, the folder is an ordinary empty "
                       "folder: what is put there stays on this computer, and is not encrypted. A "
                       "small service file makes it mount by itself. This is the file, and where "
                       "it goes:")
                  : P_("Optional: mount them at each login. A mount started by hand ends when "
                       "you log out, and until it is mounted again, the folder is an ordinary "
                       "empty folder: what is put there stays on this computer, and is not "
                       "encrypted. A small service file for each disk makes them mount by "
                       "themselves. These are the files, and where they go:"));
    for (int i = 0; i < n; i++) {
        g_autofree char *where = g_strdup_printf("~/.config/systemd/user/%s", names[i]);
        say(s, where);
        append(s, gaudit_file_field_new(texts[i]));
    }
    say(s, P_("The file also makes the folder read-only whenever nothing is mounted there, so "
              "nothing can be saved in it by mistake and stay on this computer unencrypted. "
              "While it is mounted, you can use it as any other folder."));
    say(s, n == 1 ? P_("The program writes this file and nothing else, only when you press the "
                       "button. It never writes over another file of that name.")
                  : P_("The program writes these files and nothing else, only when you press "
                       "the button. It never writes over another file of the same name."));
    buttons(s, P_("Skip"), G_CALLBACK(on_skip_unit),
            n == 1 ? P_("Write the File") : P_("Write the Files"), G_CALLBACK(on_write_unit));
}

/* --- Step 5: encryption, recommended, optional ------------------------------------ */

static void on_crypt_check(GtkButton *b, gpointer data)
{
    done(b);
    look_again(data, LOOK_CRYPT);
}

static void crypt_setup(Setup *s)
{
    g_autofree char *name = g_strdup_printf("%s-crypt", s->remote);
    g_autofree char *under = g_strdup_printf("%s:Encrypted", s->remote);
    g_autofree char *keep = g_strdup_printf("Keep this \"%s\" remote?", name);
    say(s, P_("Run rclone config again, and answer like this:"));
    command(s, "rclone config");
    const Answer a[] = {
        ANSWER_NEW,
        { "Enter name for new remote.", TRUE, name, TRUE, NULL },
        { "Option Storage.", TRUE, "crypt", TRUE, NULL },
        { "Option remote.", TRUE, under, TRUE,
          P_("The folder Encrypted on the remote you just made; rclone makes it.") },
        { "Option filename_encryption.", TRUE, "standard", TRUE, NULL },
        { "Option directory_name_encryption.", TRUE, "true", TRUE, NULL },
        { "Option password.", TRUE, "g", TRUE, P_("The password: let rclone make one.") },
        { "Password strength in bits.", TRUE, "128", TRUE, P_("128 is secure; more is fine too.") },
        { "Use this password?", TRUE, "y", TRUE, P_("Use the password rclone made.") },
        { "Option password2.", TRUE, "g", TRUE, P_("The second password, the salt: let rclone make it too.") },
        { "Password strength in bits.", TRUE, "128", TRUE, NULL },
        { "Use this password?", TRUE, "y", TRUE, NULL },
        { "Edit advanced config?", TRUE, "n", TRUE, NULL },
        ANSWER_KEEP_QUIT(keep),
    };
    answers(s, a, G_N_ELEMENTS(a));
    say(s, P_("If something goes wrong half way, remove the half-made setup with rclone config "
              "delete and its name, and start again: rclone saves as it goes."));
    say(s, P_("Write both passwords down and keep them somewhere safe, apart from this "
              "computer, such as a password manager. Without them the encrypted files cannot be "
              "read by anyone, you included, and nobody can recover them."));
    button(s, P_("Check"), TRUE, G_CALLBACK(on_crypt_check));
}

/* What the user chose: the encryption is set up first where the private
 * disk needs it and it is not there yet. */
static void chosen(Setup *s, int model)
{
    s->model = model;
    if ((model & MODEL_PRIVATE) && s->via[0] == '\0') {
        crypt_setup(s);
        return;
    }
    s->encrypted = s->via[0] != '\0';
    step_mount(s);
}

static void on_private(GtkButton *b, gpointer data)
{
    done(b);
    chosen(data, MODEL_PRIVATE);
}

static void on_shareable(GtkButton *b, gpointer data)
{
    done(b);
    chosen(data, MODEL_SHARED);
}

static void on_both(GtkButton *b, gpointer data)
{
    done(b);
    chosen(data, MODEL_BOTH);
}

static void step_model(Setup *s)
{
    say(s, P_("How will you use it? It is your choice:"));
    say(s, P_("Private: what you put there is encrypted before it leaves the computer, so the "
              "provider cannot read it. rclone does it with a second setup over the first, and "
              "you keep the passwords. Recommended."));
    say(s, P_("It encrypts what is in the files and what they are called. The service still "
              "sees how large each file is, when it was changed and uploaded, and how many "
              "files and folders there are, and that they are encrypted. So it keeps the "
              "files private, but does not hide that they are there."));
    say(s, P_("Shareable: the account as it is. The provider can read what is there, it can "
              "be shared with others, and what others share with you shows there."));
    say(s, P_("Both: two folders side by side, one of each. Choose it when the account has "
              "files already, or you share with others: you then move what is to be private "
              "yourself."));
    buttons3(s, P_("Shareable"), G_CALLBACK(on_shareable), P_("Both"), G_CALLBACK(on_both),
             P_("Private"), G_CALLBACK(on_private));
}

/* --- Step 4: rclone config ------------------------------------------------------ */

static void on_remote_check(GtkButton *b, gpointer data)
{
    done(b);
    look_again(data, LOOK_REMOTE);
}

static void step_rclone_config(Setup *s)
{
    if (services[s->service].token_page == NULL) {
        say(s, P_("Run rclone config in a terminal. It asks one thing at a time; answer like this:"));
        command(s, "rclone config");
        g_autofree char *keep =
            g_strdup_printf("Keep this \"%s\" remote?", services[s->service].remote);
        const Answer a[] = {
            ANSWER_NEW,
            { "Enter name for new remote.", TRUE, services[s->service].remote, TRUE,
              P_("Or another name, if that one is taken.") },
            { "Option Storage.", TRUE, services[s->service].type, TRUE,
              P_("Type the name, not the number: the numbers in the list change between "
                 "versions of rclone.") },
            { "Option client_id.", TRUE, NULL, FALSE, P_("Press Enter, to leave it empty.") },
            { "Option client_secret.", TRUE, NULL, FALSE, NULL },
            { "Edit advanced config?", TRUE, "n", TRUE, NULL },
            { "Use web browser to automatically authenticate rclone with remote?", TRUE,
              "y", TRUE,
              P_("The browser opens at the service: log in there and allow rclone. rclone waits "
                 "until it is done.") },
            ANSWER_KEEP_QUIT(keep),
        };
        answers(s, a, G_N_ELEMENTS(a));
        g_autofree char *how = g_strdup_printf(
            /* Translators: %s is a cloud service, e.g. "Dropbox". */
            P_("The login is made between %s and rclone on this computer: the browser hands "
               "the answer back to rclone here, and rclone keeps it in its own settings, "
               "~/.config/rclone/rclone.conf. The program never sees it. rclone logs in as its "
               "own app, which everyone who uses rclone shares, so the service may slow it "
               "down at busy times."),
            services[s->service].name);
        say(s, how);
        say(s, P_("rclone saves as it goes, also when stopped half way. If something went wrong, "
                  "remove the half-made setup with rclone config delete and its name, and start "
                  "again."));
        button(s, P_("Check"), TRUE, G_CALLBACK(on_remote_check));
        return;
    }
    say(s, P_("Run rclone config in a terminal. It asks one thing at a time; answer like this:"));
    command(s, "rclone config");
    g_autofree char *keep = g_strdup_printf("Keep this \"%s\" remote?", services[s->service].remote);
    const Answer a[] = {
        ANSWER_NEW,
        { "Enter name for new remote.", TRUE, services[s->service].remote, TRUE,
          P_("Or another name, if that one is taken.") },
        { "Option Storage.", TRUE, services[s->service].type, TRUE,
          P_("Type the name, not the number: the numbers in the list change between versions "
             "of rclone.") },
        { "Option client_id.", TRUE, NULL, FALSE, P_("Press Enter, to leave it empty.") },
        { "Option client_secret.", TRUE, NULL, FALSE, NULL },
        { "Edit advanced config?", TRUE, "n", TRUE, NULL },
        { P_("The kind of authentication"), FALSE, NULL, FALSE,
          P_("Standard, the default.") },
        { P_("The login token"), FALSE, P_("Paste the one you made"), FALSE, NULL },
        { P_("Whether to use a non-standard device or mountpoint"), FALSE, "n", TRUE,
          P_("The Archive section. y only to reach the Sync or Backup section of the service's "
             "own app.") },
        ANSWER_KEEP_QUIT(keep),
    };
    answers(s, a, G_N_ELEMENTS(a));
    say(s, P_("rclone trades the login token for a lasting one and keeps it in its own "
              "settings, ~/.config/rclone/rclone.conf. The program never sees either."));
    say(s, P_("rclone saves as it goes, also when stopped half way. If something went wrong, "
              "remove the half-made setup with rclone config delete and its name, and start "
              "again."));
    button(s, P_("Check"), TRUE, G_CALLBACK(on_remote_check));
}

/* --- Step 3: the login token ------------------------------------------------------ */

static void on_token_page(GtkButton *b, gpointer data)
{
    Setup *s = data;
    GtkUriLauncher *launcher = gtk_uri_launcher_new(services[s->service].token_page);
    GtkRoot *root = gtk_widget_get_root(GTK_WIDGET(b));
    gtk_uri_launcher_launch(launcher, GTK_IS_WINDOW(root) ? GTK_WINDOW(root) : NULL, NULL, NULL, NULL);
    g_object_unref(launcher);
}

static void on_token_done(GtkButton *b, gpointer data)
{
    done(b);
    step_rclone_config(data);
}

static void step_token(Setup *s)
{
    g_autofree char *text = g_strdup_printf(
        /* Translators: %s is a cloud service, e.g. "Jottacloud". */
        P_("Make a login token at %s: log in on its web site, open Settings, then Security, find "
           "\"Personal login token\" and press Generate. Copy what it shows. It can be used only "
           "once, and it shows up as a new device among your logged in devices there."),
        services[s->service].name);
    say(s, text);
    GtkWidget *open = gtk_button_new();
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(row), gtk_label_new(P_("Open the Security Page")));
    gtk_box_append(GTK_BOX(row), gtk_image_new_from_icon_name("gaudit-external-link-symbolic"));
    gtk_button_set_child(GTK_BUTTON(open), row);
    gtk_widget_add_css_class(open, "pill");
    gtk_widget_set_halign(open, GTK_ALIGN_START);
    g_signal_connect_data(open, "clicked", G_CALLBACK(on_token_page), setup_ref(s),
                          (GClosureNotify)(void (*)(void))setup_unref, 0);
    append(s, open);
    button(s, P_("I Have the Token"), TRUE, G_CALLBACK(on_token_done));
}

/* A token made on the service's web page first, or straight to rclone config,
 * which logs in through the browser. */
static void step_login_way(Setup *s)
{
    if (services[s->service].token_page != NULL)
        step_token(s);
    else
        step_rclone_config(s);
}

/* --- Step 2: rclone installed --------------------------------------------------- */

static void on_installed_check(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    if (g_file_test("/usr/bin/rclone", G_FILE_TEST_IS_EXECUTABLE)) {
        say(s, P_("rclone is installed."));
        step_login_way(s);
    } else {
        say(s, P_("rclone is still not installed. Install it, then open this page again."));
    }
}

static void step_installed(Setup *s)
{
    if (g_file_test("/usr/bin/rclone", G_FILE_TEST_IS_EXECUTABLE)) {
        say(s, P_("rclone is installed, from the system's packages, so it gets updates with "
                  "everything else."));
        step_login_way(s);
        return;
    }
    say(s, P_("rclone is not installed. Install it from the system's packages, so it gets "
              "updates with everything else:"));
    command(s, "sudo apt install rclone");
    button(s, P_("Check"), TRUE, G_CALLBACK(on_installed_check));
}

/* --- Step 1: the service ------------------------------------------------------------ */

static void on_service_chosen(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    if (s->dropdown != NULL) {
        guint pick = gtk_drop_down_get_selected(GTK_DROP_DOWN(s->dropdown));
        if (pick >= G_N_ELEMENTS(s->offered))
            pick = 0;
        s->service = s->offered[pick];
        gtk_widget_set_sensitive(s->dropdown, FALSE);
        if (s->service < N_SERVICES && s->addable[pick]) {
            /* The private disk mounts at login already: the shareable one beside it. */
            g_strlcpy(s->remote, s->found_remote[pick], sizeof s->remote);
            g_strlcpy(s->via, s->found_via[pick], sizeof s->via);
            s->encrypted = TRUE;
            s->adding = TRUE;
            s->model = MODEL_SHARED;
            say(s, P_("The private disk is mounted at each login already. What is left is the "
                      "shareable disk beside it."));
            step_mount(s);
            return;
        }
        if (s->service < N_SERVICES && s->login_only[pick]) {
            /* Set up already: straight to the choice, with what was found. */
            g_strlcpy(s->remote, s->found_remote[pick], sizeof s->remote);
            g_strlcpy(s->via, s->found_via[pick], sizeof s->via);
            s->encrypted = s->via[0] != '\0';
            /* Translators: %s is the name of an rclone remote, e.g. "jotta". */
            g_autofree char *text = g_strdup_printf(
                s->encrypted ? P_("rclone reaches it already, as %s, encrypted. What is left is "
                                  "choosing how to use it, and mounting it.")
                             : P_("rclone reaches it already, as %s. What is left is choosing how "
                                  "to use it, and mounting it."),
                s->remote);
            say(s, text);
            step_model(s);
            return;
        }
    }
    if (s->service >= N_SERVICES)
        s->service = 0;
    if (s->dropdown != NULL) {
        guint pick = gtk_drop_down_get_selected(GTK_DROP_DOWN(s->dropdown));
        if (pick < G_N_ELEMENTS(s->other_client) && s->other_client[pick][0] != '\0') {
            /* Translators: the first %s is a cloud service, e.g. "Dropbox", the second
             * the folder the cloud folders are gathered in, e.g. "Cloud". */
            g_autofree char *text = g_strdup_printf(
                P_("%s is set up on this computer already, with another program. Two programs "
                   "for the same account keep two copies, and can get in each other's way. "
                   "Set up only one of them; if the other one's folder is the one rclone would "
                   "use, under ~/%s, rclone cannot mount there."),
                services[s->service].name, s->gathering);
            say(s, text);
        }
    }
    step_installed(s);
}

AdwNavigationPage *gaudit_cloud_setup_page(void)
{
    AdwNavigationPage *page = gaudit_fix_page_new(
        P_("Set Up a Cloud Service With rclone"),
        P_("rclone is a program that keeps a folder in step with a cloud service. Its source "
           "code is open, the system keeps it up to date, it logs in on this computer only, and "
           "it can encrypt your files before they leave."),
        P_("This page goes through it step by step. You run the commands yourself, in a "
           "terminal: rclone asks its own questions and writes its own settings. The program "
           "writes nothing and never sees your login."),
        NULL, NULL, NULL, NULL, NULL, NULL);
    GtkWidget *box = g_object_get_data(G_OBJECT(page), "gaudit-fix-box");
    GtkWidget *anchor = g_object_get_data(G_OBJECT(page), "gaudit-fix-how");
    if (box == NULL || anchor == NULL)
        return page;
    Setup *s = g_new0(Setup, 1);
    s->refs = 1;
    s->box = box;
    g_object_add_weak_pointer(G_OBJECT(box), (gpointer *)&s->box);
    set_last(s, anchor);
    g_object_set_data_full(G_OBJECT(page), "gaudit-rclone-setup", s, setup_unref);
    gaudit_cloud_choose(g_get_home_dir(), s->gathering, sizeof s->gathering, &s->lang);
    if (!gaudit_cloud_plain_folder(s->gathering))
        g_strlcpy(s->gathering, s->lang->gathering, sizeof s->gathering);

    /* Not those rclone already reaches (from the latest collection). */
    const GauditTaskInfo *task = gaudit_task_by_id("core.cloud");
    GPtrArray *lines = task != NULL ? gaudit_cache_lines(task, NULL) : NULL;
    /* Each service as far as it has come (the latest collection): not set
     * up, the whole sequence; set up in rclone but nothing mounting it at
     * login, straight to mounting; mounted at login, not offered. */
    const char *names[16];
    char *owned[16] = { NULL };
    gsize nn = 0;
    for (guint i = 0; i < N_SERVICES && nn < G_N_ELEMENTS(names) - 1; i++) {
        gboolean there = FALSE, at_login = FALSE, private_on = FALSE, shared_there = FALSE;
        char unit_private[96], unit_shared[96], remote[128] = "", via[128] = "";
        gaudit_cloud_unit_name(&services[i], GAUDIT_CLOUD_DISK_PRIVATE, unit_private,
                               sizeof unit_private);
        gaudit_cloud_unit_name(&services[i], GAUDIT_CLOUD_DISK_SHARED, unit_shared,
                               sizeof unit_shared);
        /* Made before the two disks, one unit per service. */
        g_autofree char *unit_old = g_strdup_printf("rclone-%s.service", services[i].id);
        for (guint k = 0; lines != NULL && k < lines->len; k++) {
            gaudit_cloud_line l;
            gaudit_cloud_unit_line u;
            const char *line = g_ptr_array_index(lines, k);
            if (gaudit_cloud_parse_line(line, &l, NULL) == 1 && strcmp(l.client, "rclone") == 0
                && strcmp(l.service, services[i].id) == 0) {
                there = TRUE;
                if (remote[0] == '\0' || l.via[0] != '\0') {
                    g_strlcpy(remote, l.name, sizeof remote);
                    g_strlcpy(via, l.via, sizeof via);
                }
            } else if (gaudit_cloud_parse_line(line, &l, NULL) == 1
                       && strcmp(l.service, services[i].id) == 0 && s->other_client[nn][0] == '\0') {
                g_strlcpy(s->other_client[nn], l.client, sizeof s->other_client[nn]);
            } else if (gaudit_cloud_parse_unit(line, &u) == 3) {
                gboolean mine = strcmp(u.file, unit_private) == 0 || strcmp(u.file, unit_old) == 0;
                shared_there |= strcmp(u.file, unit_shared) == 0;
                at_login |= u.enabled && (mine || strcmp(u.file, unit_shared) == 0);
                private_on |= u.enabled && mine;
            }
        }
        /* Only the private disk at login: the shareable one can be added. */
        gboolean addable = there && via[0] != '\0' && private_on && !shared_there;
        if (there && at_login && !addable) {
            s->other_client[nn][0] = '\0';
            continue;
        }
        s->offered[nn] = i;
        s->login_only[nn] = there;
        s->addable[nn] = addable;
        g_strlcpy(s->found_remote[nn], remote, sizeof s->found_remote[nn]);
        g_strlcpy(s->found_via[nn], via, sizeof s->found_via[nn]);
        /* Translators: %s is a cloud service, e.g. "Jottacloud". */
        owned[nn] = addable ? g_strdup_printf(P_("%s: add the shareable disk"), services[i].name)
                    : there ? g_strdup_printf(P_("%s: mount at each login"), services[i].name)
                            : NULL;
        names[nn] = owned[nn] != NULL ? owned[nn] : services[i].name;
        nn++;
    }
    names[nn] = NULL;
    if (nn == 0) {
        say(s, P_("Every service this page knows how to set up is reached through rclone "
                  "already, and mounted at each login. They are in the report."));
        return page;
    }
    say(s, P_("Which cloud service?"));
    GtkWidget *dd = gtk_drop_down_new_from_strings(names);
    for (gsize i = 0; i < nn; i++)
        g_free(owned[i]);
    gtk_widget_set_halign(dd, GTK_ALIGN_START);
    s->dropdown = dd;
    g_object_add_weak_pointer(G_OBJECT(dd), (gpointer *)&s->dropdown);
    append(s, dd);
    button(s, P_("Next"), TRUE, G_CALLBACK(on_service_chosen));
    return page;
}

/* --- Files outside the encrypted folder ---------------------------------------
 *
 * Looked for only when the user presses the button, since it asks the
 * service over the network (John, 2026-11-19): "gaudit-orchestrator cloud
 * plain <remote>" counts, with rclone and its own login, and no name comes
 * back. The answer goes into the cached collection, so the report and Home
 * follow. Nothing is moved: the page says how the user moves them. */

typedef struct {
    int refs;
    char remote[128];
    char service[16];
    gboolean shareable;   /* the shareable disk is set up */
    GtkWidget *box;       /* weak */
    GtkWidget *last;      /* weak */
    char *line;
} Plain;

static void plain_unref(gpointer p)
{
    Plain *pl = p;
    if (--pl->refs > 0)
        return;
    if (pl->box != NULL)
        g_object_remove_weak_pointer(G_OBJECT(pl->box), (gpointer *)&pl->box);
    if (pl->last != NULL)
        g_object_remove_weak_pointer(G_OBJECT(pl->last), (gpointer *)&pl->last);
    g_free(pl->line);
    g_free(pl);
}

static void plain_say(Plain *pl, const char *text)
{
    if (pl->box == NULL || pl->last == NULL)
        return;
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_box_insert_child_after(GTK_BOX(pl->box), l, pl->last);
    g_object_remove_weak_pointer(G_OBJECT(pl->last), (gpointer *)&pl->last);
    pl->last = l;
    g_object_add_weak_pointer(G_OBJECT(l), (gpointer *)&pl->last);
}

static gboolean on_plain_line(const char *line, gpointer data)
{
    Plain *pl = data;
    gaudit_cloud_plain_line p;
    if (pl->line != NULL || gaudit_cloud_parse_plain(line, &p) != 0
        || strcmp(p.remote, pl->remote) != 0)
        return FALSE;
    pl->line = g_strndup(line, strcspn(line, "\n"));
    return TRUE;
}

/* The cached collection with line in place of any earlier one for the
 * same remote, just before the closing line; NULL without one. */
static GPtrArray *with_plain(GPtrArray *lines, const char *line, const char *remote)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    gboolean placed = FALSE;
    for (guint i = 0; i < lines->len; i++) {
        const char *l = g_ptr_array_index(lines, i);
        gaudit_cloud_plain_line old;
        if (gaudit_cloud_parse_plain(l, &old) == 0 && strcmp(old.remote, remote) == 0)
            continue;
        if (!placed && gaudit_cloud_parse_line(l, NULL, NULL) == 2) {
            g_ptr_array_add(out, g_strdup(line));
            placed = TRUE;
        }
        g_ptr_array_add(out, g_strdup(l));
    }
    if (!placed) {
        g_ptr_array_unref(out);
        return NULL;
    }
    return out;
}

static void on_plain_done(gboolean broken, gpointer data)
{
    Plain *pl = data;
    gaudit_cloud_plain_line p = { .status = 1 };
    gboolean got = !broken && pl->line != NULL && gaudit_cloud_parse_plain(pl->line, &p) == 0;
    if (!got || p.status == 1) {
        plain_say(pl, P_("It could not be found out. The service may not answer, this computer "
                         "may have no connection, or rclone's login may need to be renewed: "
                         "rclone config reconnect and the setup's name does that."));
    } else if (p.status == 2) {
        plain_say(pl, P_("The encryption covers all of the service, so files that are not "
                         "encrypted cannot be told apart from here."));
    } else if (p.count == 0) {
        plain_say(pl, P_("Everything there is in the encrypted folder. The provider sees only "
                         "that encrypted files are there."));
    } else {
        g_autofree char *text = p.more
            /* Translators: %u is a number, at most 1000. */
            ? g_strdup_printf(P_("More than %u files and folders there are not encrypted, so "
                                 "the provider can read them."), p.count)
            : g_strdup_printf(PN_("%u file or folder there is not encrypted, so the provider "
                                  "can read it.",
                                  "%u files and folders there are not encrypted, so the "
                                  "provider can read them.", p.count), p.count);
        plain_say(pl, text);
        plain_say(pl, pl->shareable
                          ? P_("Move what is to be private from the shareable disk to the private "
                               "one, in the file manager. It is then encrypted, and deleted from "
                               "the shareable disk, though the provider may keep the deleted "
                               "version for a while. What is to be shared stays where it is.")
                          : P_("To share them, or to make them private, set up the shareable disk: "
                               "Set Up With rclone offers it. Then move what is to be private to "
                               "the private disk, in the file manager. It is then encrypted, and "
                               "deleted from the shareable disk, though the provider may keep the "
                               "deleted version for a while."));
        plain_say(pl, P_("The program moves nothing itself: what was shared with you, or what "
                         "others use, stays where it is until you move it."));
    }
    /* Into the cached collection, so the report and Home follow. */
    const GauditTaskInfo *task = gaudit_task_by_id("core.cloud");
    GPtrArray *lines = task != NULL ? gaudit_cache_lines(task, NULL) : NULL;
    if (got && lines != NULL) {
        g_autoptr(GPtrArray) next = with_plain(lines, pl->line, pl->remote);
        if (next != NULL) {
            g_autofree char *command = g_strdup(gaudit_cache_command(task));
            g_auto(GStrv) args = gaudit_cache_args(task) != NULL
                ? g_strdupv((char **)gaudit_cache_args(task)) : NULL;
            gaudit_cache_store(task, command, next, gaudit_cache_full(task),
                               (const char *const *)args);
            gaudit_cache_changed(task);
        }
    }
    plain_unref(pl);
}

static void on_plain_look(GtkButton *b, gpointer data)
{
    Plain *pl = data;
    /* Grey whatever comes of it; opening the page again starts anew. */
    gtk_widget_set_sensitive(GTK_WIDGET(b), FALSE);
    plain_say(pl, P_("Asking the service…"));
    pl->refs++;
    const char *args[] = { "cloud", "plain", pl->remote, NULL };
    gaudit_orchestrator_start(args, 90, FALSE, on_plain_line, on_plain_done, pl);
}

AdwNavigationPage *gaudit_cloud_fix_page(const char *fix_id, GPtrArray *lines, guint item)
{
    gaudit_cloud_line f;
    if (fix_id == NULL || strcmp(fix_id, "plain") != 0 || lines == NULL || item >= lines->len
        || gaudit_cloud_parse_line(g_ptr_array_index(lines, item), &f, NULL) != 1
        || strcmp(f.client, "rclone") != 0 || !f.encrypted || !gaudit_cloud_plain_remote(f.name))
        return NULL;
    const char *name = f.service;
    for (guint i = 0; i < N_SERVICES; i++)
        if (strcmp(services[i].id, f.service) == 0)
            name = services[i].name;
    Plain *pl = g_new0(Plain, 1);
    pl->refs = 1;
    g_strlcpy(pl->remote, f.name, sizeof pl->remote);
    g_strlcpy(pl->service, f.service, sizeof pl->service);
    g_autofree char *shared_unit = g_strdup_printf("rclone-%s-shared.service", f.service);
    for (guint i = 0; i < lines->len; i++) {
        gaudit_cloud_unit_line u;
        if (gaudit_cloud_parse_unit(g_ptr_array_index(lines, i), &u) == 3
            && strcmp(u.file, shared_unit) == 0)
            pl->shareable = TRUE;
    }
    /* Translators: %s is a cloud service, e.g. "Dropbox". */
    g_autofree char *title = g_strdup_printf(P_("Unencrypted Files at %s"), name);
    g_autofree char *what = g_strdup_printf(
        P_("rclone encrypts what goes through the private disk, and keeps it in one folder at "
           "%s. Anything else there, from before or put there another way, the provider can "
           "read."), name);
    g_autofree char *how = g_strdup_printf(
        P_("The program can ask %s how many files and folders lie outside the encrypted folder. "
           "It asks over the network, with rclone and rclone's own login, and only when you press "
           "the button. Only how many comes back: no names are kept or shown."), name);
    AdwNavigationPage *page = gaudit_fix_page_new(title, what, how, NULL, NULL, NULL, NULL, NULL,
                                                  NULL);
    GtkWidget *box = g_object_get_data(G_OBJECT(page), "gaudit-fix-box");
    GtkWidget *anchor = g_object_get_data(G_OBJECT(page), "gaudit-fix-how");
    if (box == NULL || anchor == NULL) {
        plain_unref(pl);
        return page;
    }
    pl->box = box;
    g_object_add_weak_pointer(G_OBJECT(box), (gpointer *)&pl->box);
    pl->last = anchor;
    g_object_add_weak_pointer(G_OBJECT(anchor), (gpointer *)&pl->last);
    g_object_set_data_full(G_OBJECT(page), "gaudit-cloud-plain", pl, plain_unref);
    /* Translators: %s is a cloud service, e.g. "Dropbox". */
    g_autofree char *label = g_strdup_printf(P_("Look at %s"), name);
    GtkWidget *b = gaudit_action_button_new(label, FALSE, TRUE);
    gtk_widget_set_halign(b, GTK_ALIGN_END);
    g_signal_connect(b, "clicked", G_CALLBACK(on_plain_look), pl);
    gtk_box_insert_child_after(GTK_BOX(box), b, anchor);
    g_object_remove_weak_pointer(G_OBJECT(pl->last), (gpointer *)&pl->last);
    pl->last = b;
    g_object_add_weak_pointer(G_OBJECT(b), (gpointer *)&pl->last);
    return page;
}
