/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "cloud.h"
#include "gaudit-cloud.h"
#include "gaudit-orchestrator.h"
#include "gaudit-report-run.h"
#include "gaudit-session.h"
#include "gaudit-task-page.h"
#include "gaudit-task.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_CLOUD_DOMAIN, s)

gboolean gaudit_cloud_line_ok(const char *line, gboolean *last)
{
    int kind = gaudit_cloud_parse_line(line, NULL, NULL);
    *last = kind == 2;
    return kind > 0 || gaudit_cloud_parse_unit(line, NULL) == 3;
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
    char via[128];       /* the crypt remote over it, found */
} Setup;

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

/* A step is over: its button, and a partner beside it, go grey. */
static void done(GtkButton *b)
{
    gtk_widget_set_sensitive(GTK_WIDGET(b), FALSE);
    GtkWidget *other = g_object_get_data(G_OBJECT(b), "gaudit-other");
    if (other != NULL)
        gtk_widget_set_sensitive(other, FALSE);
}

static const char *mount_remote(Setup *s, char *buf, size_t len);
static void step_mount(Setup *s);
static void step_login(Setup *s);
static void step_encrypt(Setup *s);
static void step_rclone_config(Setup *s);
static void step_token(Setup *s);

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
    gboolean found = FALSE, encrypted = FALSE, unit_on = FALSE;
    char name[128] = "", unit_file[64];
    gaudit_cloud_unit_name(&services[s->service], unit_file, sizeof unit_file);
    for (guint i = 0; status == GAUDIT_RUN_OK && result != NULL && result->lines != NULL
                      && i < result->lines->len; i++) {
        gaudit_cloud_unit_line u;
        if (gaudit_cloud_parse_unit(g_ptr_array_index(result->lines, i), &u) == 3
            && strcmp(u.file, unit_file) == 0 && u.enabled && u.mounted)
            unit_on = TRUE;
    }
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
        say(s, unit_on ? P_("Found: the service is switched on, and the folder is mounted.")
                       : P_("The service is not switched on and mounted yet. Run the commands "
                            "above, then open this page again."));
    } else if (a->look == LOOK_REMOTE && found) {
        g_strlcpy(s->remote, name, sizeof s->remote);
        /* Translators: %s is the name of an rclone remote, e.g. "jotta". */
        g_autofree char *text = g_strdup_printf(P_("Found: rclone has a setup named %s."), name);
        say(s, text);
        step_encrypt(s);
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

/* --- Step 6: mounting ---------------------------------------------------------- */

static void step_mount(Setup *s)
{
    char which[160];
    mount_remote(s, which, sizeof which);
    g_autofree char *mkdir = g_strdup_printf("mkdir -p ~/Cloud/%s", services[s->service].name);
    g_autofree char *mount = g_strdup_printf(
        "rclone mount %s: ~/Cloud/%s --volname %s --umask 077 --vfs-cache-mode full "
        "--dir-cache-time 1h --daemon",
        which, services[s->service].name, services[s->service].name);
    say(s, P_("Last, make a folder for it under ~/Cloud, where the cloud folders are gathered, "
              "and mount it there. Run these in a terminal:"));
    command(s, mkdir);
    command(s, mount);
    say(s, P_("--vfs-cache-mode full keeps a copy of what is used on this computer, and "
              "--dir-cache-time remembers the lists of files for an hour: without them, Files "
              "fetches every file to show the folder, which can take minutes. --volname gives it "
              "the name the file manager shows, and --umask 077 shows what is there as yours "
              "alone, as it is: other accounts cannot reach a mount like this. --daemon lets it "
              "run in the background until you log out. To mount it each time you log in, "
              "rclone's own documentation shows how."));
    if (s->encrypted)
        say(s, P_("Use the encrypted setup, as above, for everything you put there: what goes "
                  "through the other one is not encrypted."));
    step_login(s);
}

/* --- Step 7: mounting at each login, optional --------------------------------------
 *
 * A systemd user unit, written only on the user's informed choice: the page
 * shows the very text and where it goes (from common/cloud.h, the same
 * function the orchestrator writes it with), and nothing is written until
 * the button is pressed. Enabling it is the user's own command. */

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

static void on_unit_written(gboolean broken, gpointer data)
{
    Written *w = data;
    Setup *s = w->s;
    char name[64];
    gaudit_cloud_unit_name(&services[s->service], name, sizeof name);
    if (broken || (strcmp(w->result, "written") != 0 && strcmp(w->result, "unchanged") != 0)) {
        say(s, strcmp(w->result, "foreign") == 0
                   ? P_("A file of that name is there already, and it is not this one, so it was "
                        "left as it is.")
                   : P_("The file could not be written."));
    } else {
        say(s, strcmp(w->result, "written") == 0 ? P_("Written.") : P_("It was there already, "
                                                                          "the same."));
        g_autofree char *stop = g_strdup_printf("fusermount -u ~/Cloud/%s", services[s->service].name);
        g_autofree char *enable = g_strdup_printf("systemctl --user enable --now %s", name);
        say(s, P_("Now stop the mount started by hand, if it runs, and switch the service on. "
                  "Run these in a terminal:"));
        command(s, stop);
        command(s, "systemctl --user daemon-reload");
        command(s, enable);
        say(s, P_("It then mounts the folder at each login, and starts it again if it stops."));
        button(s, P_("Check"), TRUE, G_CALLBACK(on_unit_check));
    }
    setup_unref(s);
    g_free(w);
}

static void on_write_unit(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    char remote[160];
    Written *w = g_new0(Written, 1);
    w->s = setup_ref(s);
    const char *args[] = { "cloud", "unit", services[s->service].id,
                           mount_remote(s, remote, sizeof remote), NULL };
    gaudit_orchestrator_start(args, 30, FALSE, on_unit_line, on_unit_written, w);
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
    char remote[160], text[4096], name[64];
    if (gaudit_cloud_unit_text(&services[s->service], mount_remote(s, remote, sizeof remote), text,
                               sizeof text) != 0)
        return;  /* a remote name that may not go into a file: the user mounts by hand */
    gaudit_cloud_unit_name(&services[s->service], name, sizeof name);
    say(s, P_("Optional: mount it at each login. A mount started by hand ends when you log out, "
              "and until it is mounted again, the folder is an ordinary empty folder: what is "
              "put there stays on this computer, and is not encrypted. A small service file "
              "makes it mount by itself. This is the file, and where it goes:"));
    /* Translators: %s is a file name, e.g. "rclone-jottacloud.service". */
    g_autofree char *where = g_strdup_printf("~/.config/systemd/user/%s", name);
    say(s, where);
    append(s, gaudit_file_field_new(text));
    say(s, P_("The file also makes the folder read-only whenever nothing is mounted there, so "
              "nothing can be saved in it by mistake and stay on this computer unencrypted. "
              "While it is mounted, you can use it as any other folder."));
    say(s, P_("The program writes this file and nothing else, only when you press the button. "
              "It never writes over another file of that name."));
    buttons(s, P_("Skip"), G_CALLBACK(on_skip_unit), P_("Write the File"), G_CALLBACK(on_write_unit));
}

/* --- Step 5: encryption, recommended, optional ------------------------------------ */

static void on_crypt_check(GtkButton *b, gpointer data)
{
    done(b);
    look_again(data, LOOK_CRYPT);
}

static void on_encrypt(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    g_autofree char *text = g_strdup_printf(
        /* Translators: the rclone remote's name, twice, then the name to give the new one. */
        P_("Run rclone config again, and answer:\n"
           "· n, a new remote\n"
           "· name: %s-crypt\n"
           "· storage: type crypt\n"
           "· remote: %s:Encrypted\n"
           "· filename_encryption: standard\n"
           "· directory_name_encryption: true\n"
           "· password: g, to let rclone make one; Bits: 128 or more (128 is secure); then y to "
           "use it\n"
           "· password2, the salt: g again, the same number of bits, then y\n"
           "· edit advanced config: n\n"
           "· then y to keep it, and q to quit"),
        s->remote, s->remote);
    say(s, text);
    command(s, "rclone config");
    say(s, P_("If something goes wrong half way, remove the half-made setup with rclone config "
              "delete and its name, and start again: rclone saves as it goes."));
    say(s, P_("Write both passwords down and keep them somewhere safe, apart from this "
              "computer, such as a password manager. Without them the encrypted files cannot be "
              "read by anyone, you included, and nobody can recover them."));
    button(s, P_("Check"), TRUE, G_CALLBACK(on_crypt_check));
}

static void on_skip_encrypt(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    say(s, P_("Without encryption the provider can read what you send there. It can be added "
              "later the same way."));
    step_mount(s);
}

static void step_encrypt(Setup *s)
{
    say(s, P_("Recommended: encrypt the files before they leave the computer, so the provider "
              "cannot read them. rclone does it with a second setup over the first, and you "
              "keep the passwords. It is optional; you choose."));
    say(s, P_("It encrypts what is in the files and what they are called. The service still "
              "sees how large each file is, when it was changed and uploaded, and how many "
              "files and folders there are, and that they are encrypted. So it keeps the "
              "files private, but does not hide that they are there."));
    buttons(s, P_("Skip"), G_CALLBACK(on_skip_encrypt), P_("Set Up Encryption"), G_CALLBACK(on_encrypt));
}

/* --- Step 4: rclone config ------------------------------------------------------ */

static void on_remote_check(GtkButton *b, gpointer data)
{
    done(b);
    look_again(data, LOOK_REMOTE);
}

static void step_rclone_config(Setup *s)
{
    g_autofree char *text = g_strdup_printf(
        /* Translators: the name suggested for the remote, then rclone's storage type. */
        P_("Run rclone config in a terminal, and answer:\n"
           "· n, a new remote\n"
           "· name: %s (or another, if that one is taken)\n"
           "· storage: type %s (the name, since the numbers in the list change between "
           "versions of rclone)\n"
           "· client_id and client_secret: press Enter, to leave them empty\n"
           "· edit advanced config: n\n"
           "· authentication: 1, standard (the default)\n"
           "· the login token: paste the one you made\n"
           "· a non-standard device or mountpoint: n, for the Archive section (y only to reach "
           "the Sync or Backup section of the service's own app)\n"
           "· then y to keep it, and q to quit"),
        services[s->service].remote, services[s->service].type);
    say(s, text);
    command(s, "rclone config");
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

/* --- Step 2: rclone installed --------------------------------------------------- */

static void on_installed_check(GtkButton *b, gpointer data)
{
    Setup *s = data;
    done(b);
    if (g_file_test("/usr/bin/rclone", G_FILE_TEST_IS_EXECUTABLE)) {
        say(s, P_("rclone is installed."));
        step_token(s);
    } else {
        say(s, P_("rclone is still not installed. Install it, then open this page again."));
    }
}

static void step_installed(Setup *s)
{
    if (g_file_test("/usr/bin/rclone", G_FILE_TEST_IS_EXECUTABLE)) {
        say(s, P_("rclone is installed, from the system's packages, so it gets updates with "
                  "everything else."));
        step_token(s);
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
        if (s->service < N_SERVICES && s->login_only[pick]) {
            /* Set up already: straight to mounting it, with what was found. */
            g_strlcpy(s->remote, s->found_remote[pick], sizeof s->remote);
            g_strlcpy(s->via, s->found_via[pick], sizeof s->via);
            s->encrypted = s->via[0] != '\0';
            /* Translators: %s is the name of an rclone remote, e.g. "jotta". */
            g_autofree char *text = g_strdup_printf(
                s->encrypted ? P_("rclone reaches it already, as %s, encrypted. What is left is "
                                  "mounting it.")
                             : P_("rclone reaches it already, as %s. What is left is mounting it."),
                s->remote);
            say(s, text);
            step_mount(s);
            return;
        }
    }
    if (s->service >= N_SERVICES)
        s->service = 0;
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
        gboolean there = FALSE, at_login = FALSE;
        char unit_file[64], remote[128] = "", via[128] = "";
        gaudit_cloud_unit_name(&services[i], unit_file, sizeof unit_file);
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
            } else if (gaudit_cloud_parse_unit(line, &u) == 3 && strcmp(u.file, unit_file) == 0
                       && u.enabled) {
                at_login = TRUE;
            }
        }
        if (there && at_login)
            continue;
        s->offered[nn] = i;
        s->login_only[nn] = there;
        g_strlcpy(s->found_remote[nn], remote, sizeof s->found_remote[nn]);
        g_strlcpy(s->found_via[nn], via, sizeof s->found_via[nn]);
        /* Translators: %s is a cloud service, e.g. "Jottacloud". */
        owned[nn] = there ? g_strdup_printf(P_("%s: mount at each login"), services[i].name) : NULL;
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
