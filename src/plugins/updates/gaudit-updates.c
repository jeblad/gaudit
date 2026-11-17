/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <pwd.h>
#include <unistd.h>

#include "gaudit-updates.h"
#include "gaudit-sourceless-page.h"
#include "gaudit-task-page.h"
#include "gaudit-session.h"
#include "gaudit-task.h"
#include "updates.h"
#include "apt-ops.h"
#include "vendor.h"
#include "gaudit-report-run.h"
#include "gaudit-orchestrator.h"
#include "gaudit/run.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_UPDATES_DOMAIN, s)
#define PN_(one, many, n) g_dngettext(GAUDIT_UPDATES_DOMAIN, one, many, n)

gboolean gaudit_updates_line(const char *line, gboolean *last)
{
    gaudit_update_fact f;
    unsigned count;
    int kind = gaudit_update_parse_line(line, &f, &count);
    *last = kind == 2;
    if (kind == 1 || kind == 2)
        return TRUE;
    gaudit_update_vendor v;
    if (gaudit_update_parse_vendor(line, &v) == 0)
        return gaudit_vendor_find(v.id) != NULL;  /* only what gAudit's table knows */
    gaudit_update_latest l;
    if (gaudit_update_parse_latest(line, &l) == 0)
        return gaudit_vendor_find(l.id) != NULL;
    gaudit_update_local lc;
    if (gaudit_update_parse_local(line, &lc) == 0)
        return gaudit_vendor_local_find(lc.id) != NULL;
    gaudit_update_companion cc;
    if (gaudit_update_parse_companion(line, &cc) == 0)
        return gaudit_vendor_companion_find(cc.id) != NULL;
    /* The package files, from the helper (the session takes them from no
     * one else): its findings and its result, in their own strict format. */
    gaudit_run_event ev;
    return gaudit_run_parse_line(line, &ev) == 0
           && (ev.type == GAUDIT_RUN_EVENT_INTEGRITY_FILE || ev.type == GAUDIT_RUN_EVENT_INTEGRITY);
}

/* The fact with key in lines, or FALSE. */
static gboolean find_fact(GPtrArray *lines, gaudit_update_key key, gaudit_update_fact *out)
{
    for (guint i = 0; i < lines->len; i++) {
        unsigned count;
        if (gaudit_update_parse_line(g_ptr_array_index(lines, i), out, &count) == 1
            && out->key == key)
            return TRUE;
    }
    return FALSE;
}

/* The commands per backend: fixed, never from the collection or the
 * report. NULL where the backend has none. */
typedef struct {
    const char *backend;
    const char *look;     /* look for updates now */
    const char *install;  /* install what waits */
    const char *timers;   /* switch the daily jobs on */
} commands;

static const commands table[] = {
    /* Debian's are steps from the shared table (debian_steps), with a run
     * button; never a compound command. */
    { "debian", NULL, NULL, NULL },
    { "fedora", "sudo dnf check-update --refresh", "sudo dnf upgrade --refresh", NULL },
    /* Never "pacman -Sy" alone: a partial upgrade can break the system. */
    { "arch", NULL, "sudo pacman -Syu", NULL },
};

static const commands *commands_for(GPtrArray *lines)
{
    gaudit_update_fact f;
    if (!find_fact(lines, GAUDIT_UPDATE_BACKEND, &f) || f.status != GAUDIT_FACT_KNOWN)
        return NULL;
    for (gsize i = 0; i < G_N_ELEMENTS(table); i++)
        if (strcmp(table[i].backend, f.text) == 0)
            return &table[i];
    return NULL;
}

/* Checking again after a change: the Updates collection anew, which Home
 * and the report follow. */
static void on_recollected(gaudit_run_status status, const GauditRunResult *result, gpointer data)
{
    (void)status;
    (void)result;
    (void)data;
}

static void recollect(gpointer data)
{
    (void)data;
    const GauditTaskInfo *task = gaudit_task_by_id("core.updates");
    if (task == NULL)
        return;
    /* The same depth as the report the page came from (the package files
     * again after a reinstall), else Home's quick one. */
    const char *command = gaudit_cache_command(task);
    if (command == NULL)
        command = gaudit_task_home_command(task, GAUDIT_LEVEL_QUICK);
    gaudit_session_run_args(command, gaudit_cache_full(task) ? gaudit_cache_args(task) : NULL,
                            NULL, on_recollected, NULL);
}

/* --- Debian: steps from the shared table ----------------------------------
 *
 * The command shown is the helper's argv (common/apt-ops.h), and what each
 * part does is said in plain words, so pressing Run or copying it is an
 * informed choice. */

static gsize apt_explain(const char *op, const char **out)
{
    gsize n = 0;
    if (strcmp(op, "apt-update") == 0)
        out[n++] = P_("apt-get update fetches the newest lists of updates from your software "
                      "sources. Nothing is installed.");
    if (strcmp(op, "apt-upgrade-update") == 0)
        out[n++] = P_("--update first fetches the newest lists of updates.");
    if (strcmp(op, "apt-upgrade") == 0 || strcmp(op, "apt-upgrade-update") == 0) {
        out[n++] = P_("upgrade installs the updates that are waiting.");
        out[n++] = P_("--with-new-pkgs may also install new packages an update needs; it never "
                      "removes any.");
    }
    if (strcmp(op, "reinstall") == 0)
        out[n++] = P_("install --reinstall installs these packages again, which puts their own "
                      "files back.");
    if (strcmp(op, "apt-upgrade") == 0 || strcmp(op, "apt-upgrade-update") == 0
        || strcmp(op, "reinstall") == 0) {
        out[n++] = P_("-y answers yes on your behalf, so it does not stop to ask.");
        out[n++] = P_("The two --force-conf options: where you have changed a settings file and "
                      "the package brings a new one, your version is kept.");
        out[n++] = P_("Packages that are not signed are never installed: apt stops instead.");
    }
    if (strcmp(op, "add-ppa") == 0) {
        out[n++] = P_("add-apt-repository sets the PPA up again for the release this computer "
                      "runs, with its signing key from Launchpad, and then fetches the lists of "
                      "updates.");
        out[n++] = P_("-y answers yes on your behalf, so it does not stop to ask.");
        out[n++] = P_("Afterwards, the program checks that the PPA could be read for this "
                      "release: add-apt-repository does not say so itself.");
    }
    if (strcmp(op, "enable-apt-timers") == 0) {
        out[n++] = P_("enable --now switches the jobs on now, and at every start.");
        out[n++] = P_("apt-daily.timer looks for updates every day; apt-daily-upgrade.timer "
                      "installs them, as set up.");
    }
    out[n++] = P_("sudo runs it with administrator rights. From this page, the switch beside the "
                  "title asks for the password.");
    if (strcmp(op, "apt-update") != 0)
        out[n++] = P_("It cannot be undone from here: what it changes is up to the tool and the "
                      "packages, and not all of it can be known beforehand.");
    out[n] = NULL;
    return n;
}

/* One step: the shown command, the run arguments and the explanation, kept
 * together until the page has copied them. */
typedef struct {
    char shown[1024];
    char *run[4 + GAUDIT_APT_MAX_PACKAGES];
    char arg[128];  /* a single argument kept here (add-ppa) */
    const char *explain[12];
    GauditFixStep step;
} AptStep;

static gboolean apt_step(AptStep *a, const char *op, const char *const *packages, gsize n)
{
    const gaudit_apt_op *o = gaudit_apt_op_find(op);
    if (o == NULL || gaudit_apt_op_shown(o, packages, n, a->shown, sizeof a->shown) != 0)
        return FALSE;
    gsize k = 0;
    a->run[k++] = (char *)"session";
    a->run[k++] = (char *)"run";
    a->run[k++] = (char *)o->name;
    for (gsize i = 0; i < n; i++)
        a->run[k++] = (char *)packages[i];
    a->run[k] = NULL;
    apt_explain(op, a->explain);
    a->step = (GauditFixStep){ a->shown, (const char *const *)a->run, a->explain, NULL };
    if (strcmp(op, "add-ppa") == 0)
        /* The PPA is then set up, but has nothing for this release: every
         * look for updates gives the same error until it is off again. */
        a->step.failed = P_("The PPA was set up, but could not be read for this release, so it "
                            "most likely has no packages for it yet. It now gives the same error "
                            "every time updates are looked for, so switch it off again: in "
                            "Software & Updates, under Other Software, take the tick off its "
                            "line for this release.");
    return TRUE;
}

/* Whether the upgrade can fetch the lists itself (apt 2.7.0 and newer). */
static gboolean upgrade_updates(GPtrArray *lines)
{
    gaudit_update_fact f;
    return find_fact(lines, GAUDIT_UPDATE_UPGRADE_UPDATES, &f) && f.status == GAUDIT_FACT_KNOWN
           && f.value == 1;
}

/* Installing automatically. With an admin tool that sets updates up
 * (Software Updater, Synaptic, ...), the setting is left to it: a file of
 * gAudit's would override what the tool shows and sets. Without one, on
 * Debian and Ubuntu, gAudit can write its own drop-in, and take it away
 * again (conf-write.h decides whether it may). on: already installed
 * automatically. */
static AdwNavigationPage *automatic_page(GPtrArray *lines, gboolean on, const commands *cmd)
{
    gaudit_update_fact tools, own;
    gboolean have_tools = find_fact(lines, GAUDIT_UPDATE_ADMIN_TOOLS, &tools)
                          && tools.status == GAUDIT_FACT_KNOWN;
    gboolean mine = find_fact(lines, GAUDIT_UPDATE_OWN_SETTING, &own)
                    && own.status == GAUDIT_FACT_KNOWN && own.value == 1;
    gboolean debian = cmd != NULL && strcmp(cmd->backend, "debian") == 0;
    GauditConfAction a = {
        P_("Switch On"),
        P_("Writes the program's own file /etc/apt/apt.conf.d/52gaudit-automatic-updates: this "
           "computer then looks for updates every day and installs them as unattended-upgrades is "
           "set up (on Debian and Ubuntu: security updates). It can be removed again here."),
        "run automatic-updates-on",
    };
    GauditConfAction u = {
        P_("Remove the Program's Setting"),
        P_("Removes the program's own file /etc/apt/apt.conf.d/52gaudit-automatic-updates, if it "
           "is still as the program wrote it. Settings made elsewhere are not touched."),
        "run automatic-updates-remove",
    };
    /* Set up by gAudit: its own setting, which it can take away again;
     * once taken away, it can be switched on here again. */
    if (debian && on && mine)
        return gaudit_fix_page_new_conf(
            P_("Install Updates Automatically"),
            P_("The program has set this computer up to install updates by itself."),
            P_("It is the program's own setting, and it can be taken away again here. Then the "
               "computer's other settings decide."),
            NULL, &a, &u, TRUE, recollect, NULL, NULL);
    if (debian && have_tools && tools.value == 0)
        return gaudit_fix_page_new_conf(
            P_("Install Updates Automatically"),
            P_("Updates are not installed by themselves on this computer, so it is only as up to "
               "date as the last time someone installed them."),
            P_("The program can switch it on with a setting of its own: security updates are then "
               "installed by themselves. You are asked to confirm first, and it can be taken away "
               "again here."),
            P_("If it is off on purpose, for example because changes must be planned, keep it off "
               "and install the updates regularly yourself."),
            &a, &u, mine, recollect, NULL, NULL);
    g_autofree char *with_tool = have_tools && tools.value > 0
        /* Translators: %s is a list of programs, e.g. "update-manager, synaptic". */
        ? g_strdup_printf(P_("Switch it on in your update program (%s): choose to install security "
                             "updates automatically. Other updates can still wait for you."),
                          tools.text)
        : NULL;
    return gaudit_fix_page_new(
        P_("Install Updates Automatically"),
        P_("Updates are not installed by themselves on this computer, so it is only as up to "
           "date as the last time someone installed them."),
        with_tool != NULL ? with_tool
            : P_("In your system's settings for software updates, choose to install security updates "
                 "automatically. Other updates can still wait for you."),
        NULL,
        P_("If it is off on purpose, for example because changes must be planned, keep it off "
           "and install the updates regularly yourself."),
        NULL, NULL, NULL, NULL);
}

/* The command comes from the fixed table above, never from the report: a
 * rule can name a fix, not write one. None of them runs from here: they
 * need the administrator's password, and with an admin tool installed its
 * own plugin is the place for the button. */
/* --- Known vendor packages -------------------------------------------------- */

/* The page's state, shared by what runs from it: it lives as long as the
 * page or a run still needs it, and its widgets are weak, so a run that
 * ends after the page is gone changes nothing on screen. */
typedef struct {
    gint ref;
    char id[32];
    char version[40];            /* the newer version, once known */
    char *download;              /* the user's download, until it is checked */
    GtkWidget *check, *latest;   /* weak: Check for a New Version, and what it found */
    GtkWidget *install, *status; /* weak: Install, and how it went */
    GtkWidget *weak, *anyway;    /* weak: why the signature is weaker, Install Anyway */
} VendorUi;

static void weak_set(GtkWidget **slot, GtkWidget *w)
{
    *slot = w;
    g_object_add_weak_pointer(G_OBJECT(w), (gpointer *)slot);
}

static void weak_clear(GtkWidget **slot)
{
    if (*slot != NULL)
        g_object_remove_weak_pointer(G_OBJECT(*slot), (gpointer *)slot);
    *slot = NULL;
}

/* The download is the user's to keep tidy: gone once checked, or when the
 * page closes, never left in a folder nobody looks in. Only a path of the
 * shape the orchestrator makes is ever removed. */
static void forget_download(VendorUi *ui)
{
    if (ui->download != NULL && gaudit_vendor_verify_args_ok(ui->id, "1", ui->download)) {
        g_unlink(ui->download);
        g_autofree char *dir = g_path_get_dirname(ui->download);
        g_rmdir(dir);
    }
    g_clear_pointer(&ui->download, g_free);
}

static VendorUi *ui_ref(VendorUi *ui)
{
    g_atomic_int_inc(&ui->ref);
    return ui;
}

static void ui_unref(gpointer data)
{
    VendorUi *ui = data;
    if (!g_atomic_int_dec_and_test(&ui->ref))
        return;
    forget_download(ui);
    weak_clear(&ui->check);
    weak_clear(&ui->latest);
    weak_clear(&ui->install);
    weak_clear(&ui->status);
    weak_clear(&ui->weak);
    weak_clear(&ui->anyway);
    g_free(ui);
}

static void say(GtkWidget *label, const char *text)
{
    if (label == NULL)
        return;
    gtk_label_set_text(GTK_LABEL(label), text);
    gtk_widget_set_visible(label, TRUE);
}

static void grey(GtkWidget *button)
{
    if (button != NULL)
        gtk_widget_set_sensitive(button, FALSE);
}

/* What the page says once a newer version is known (or not), and the
 * Install button with it: Check for a New Version then goes grey. */
static void show_latest(VendorUi *ui, const gaudit_update_latest *l)
{
    const gaudit_vendor_package *p = gaudit_vendor_find(ui->id);
    if (p == NULL)
        return;
    if (l->status == 0 && l->newer && p->key_file == NULL) {
        /* Nothing to check it with: shown, never installed. */
        g_autofree char *text = g_strdup_printf(
            /* Translators: the newest version, the one installed, who makes it (three
             * times), then the address of their download page. */
            P_("Version %s is out; this computer has %s. %s does not sign its package, so the "
               "program cannot check that %s made it, and does not install it. Download it from "
               "%s's own page: %s"),
            l->version, l->installed, p->vendor, p->vendor, p->vendor, p->download);
        say(ui->latest, text);
        grey(ui->check);
    } else if (l->status == 0 && l->newer) {
        g_autofree char *text = g_strdup_printf(
            /* Translators: the newest version, the one installed, then who makes it. */
            P_("Version %s is out; this computer has %s. The program can download it from %s, "
               "check that %s signed it, and install it."),
            l->version, l->installed, p->vendor, p->vendor);
        say(ui->latest, text);
        g_strlcpy(ui->version, l->version, sizeof ui->version);
        grey(ui->check);
        if (ui->install != NULL)
            gtk_widget_set_visible(ui->install, TRUE);
    } else if (l->status == 0) {
        g_autofree char *text = g_strdup_printf(P_("This computer has the newest version, %s."),
                                                l->version);
        say(ui->latest, text);
    } else {
        say(ui->latest, P_("It could not be found out. The page may not answer, or this "
                           "computer may have no connection."));
    }
}

/* --- Looking for the newest version --- */

typedef struct {
    VendorUi *ui;
    char *line;
} LatestRun;

static gboolean on_latest_line(const char *line, gpointer user_data)
{
    LatestRun *r = user_data;
    gaudit_update_latest l;
    if (r->line != NULL || gaudit_update_parse_latest(line, &l) != 0 || strcmp(l.id, r->ui->id) != 0)
        return FALSE;
    r->line = g_strndup(line, strcspn(line, "\n"));
    return TRUE;
}

/* The cached Updates collection with line in place of any earlier result
 * for the same package, just before the closing line; NULL when there is
 * no closing line to put it before. */
static GPtrArray *with_latest(GPtrArray *lines, const char *line, const char *id)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(g_free);
    gboolean placed = FALSE;
    for (guint i = 0; i < lines->len; i++) {
        const char *l = g_ptr_array_index(lines, i);
        gaudit_update_latest old;
        gaudit_update_fact f;
        unsigned count;
        if (gaudit_update_parse_latest(l, &old) == 0 && strcmp(old.id, id) == 0)
            continue;
        if (!placed && gaudit_update_parse_line(l, &f, &count) == 2) {
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

static void on_latest_done(gboolean broken, gpointer user_data)
{
    LatestRun *r = user_data;
    VendorUi *ui = r->ui;
    gaudit_update_latest l = { .status = 1 };
    gboolean got = !broken && r->line != NULL && gaudit_update_parse_latest(r->line, &l) == 0;
    /* The button stays grey whatever came of it: its sequence is over. A
     * new one starts when the page is opened again. */
    show_latest(ui, &l);
    /* Into the cached collection, so the report and Home follow. */
    const GauditTaskInfo *task = gaudit_task_by_id("core.updates");
    GPtrArray *lines = task != NULL ? gaudit_cache_lines(task, NULL) : NULL;
    if (got && lines != NULL) {
        g_autoptr(GPtrArray) next = with_latest(lines, r->line, ui->id);
        if (next != NULL) {
            g_autofree char *command = g_strdup(gaudit_cache_command(task));
            g_auto(GStrv) args = gaudit_cache_args(task) != NULL
                ? g_strdupv((char **)gaudit_cache_args(task)) : NULL;
            gaudit_cache_store(task, command, next, gaudit_cache_full(task),
                               (const char *const *)args);
            gaudit_cache_changed(task);
        }
    }
    g_free(r->line);
    ui_unref(ui);
    g_free(r);
}

static void on_check_latest(GtkButton *button, gpointer user_data)
{
    VendorUi *ui = user_data;
    LatestRun *r = g_new0(LatestRun, 1);
    r->ui = ui_ref(ui);
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
    say(ui->latest, P_("Looking for the newest version…"));
    const char *args[] = { "updates", "latest", ui->id, NULL };
    gaudit_orchestrator_start(args, 60, FALSE, on_latest_line, on_latest_done, r);
}

/* --- Installing: download, check, install --- */

/* What a refusal or an outcome means, in gAudit's own words. */
static char *vendor_outcome_text(const gaudit_vendor_package *p, const gaudit_vendor_report *v)
{
    const char *r = v->result;
    if (strcmp(r, "installed") == 0)
        /* Translators: a program's name, then its version. */
        return g_strdup_printf(P_("Installed: %s now has version %s."), p->title, v->version);
    if (strcmp(r, "failed") == 0)
        return g_strdup(P_("Installing stopped with an error. Look for updates and try again, or "
                           "install it from the maker's page."));
    if (strcmp(r, "no-file") == 0)
        return g_strdup(P_("The download could not be read, so nothing was installed."));
    if (strcmp(r, "too-large") == 0)
        return g_strdup(P_("The download is larger than the program accepts, so nothing was installed."));
    if (strcmp(r, "not-signed") == 0)
        return g_strdup(P_("The package is not signed, so who made it cannot be checked. It was "
                           "not installed."));
    if (strcmp(r, "unknown-key") == 0)
        return g_strdup_printf(
            /* Translators: %s is who makes the program, twice. */
            P_("The package is signed with a key the program does not know for %s, so it was not "
               "installed. If %s has changed its key, a newer version of the program will know it; "
               "until then, install it from the maker's page yourself."), p->vendor, p->vendor);
    if (strcmp(r, "bad-signature") == 0)
        return g_strdup(P_("The signature does not match the package. It was not installed."));
    if (strcmp(r, "weak-md5") == 0)
        return g_strdup(P_("The signature rests on MD5 alone, which says nothing about who made "
                           "the package. It was not installed."));
    if (strcmp(r, "mismatch") == 0)
        return g_strdup(P_("The package's contents do not match its signature. It was not "
                           "installed."));
    if (strcmp(r, "wrong-package") == 0)
        return g_strdup(P_("The download is not the package and version expected. It was not "
                           "installed."));
    if (strcmp(r, "not-newer") == 0)
        return g_strdup(P_("The download is not newer than the version installed. It was not "
                           "installed."));
    if (strcmp(r, "not-verified") == 0)
        return g_strdup(P_("The checked package is gone, for one when the administrator rights "
                           "ended in between. Nothing was installed."));
    return g_strdup(P_("It could not be checked or installed."));
}

static void ended(VendorUi *ui, gaudit_run_status status, const GauditRunResult *result)
{
    const gaudit_vendor_package *p = gaudit_vendor_find(ui->id);
    if (status == GAUDIT_RUN_CANCELLED || status == GAUDIT_RUN_DENIED) {
        say(ui->status, P_("Cancelled, so nothing was installed."));
    } else if (status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_VENDOR
               && p != NULL) {
        g_autofree char *text = vendor_outcome_text(p, &result->vendor);
        say(ui->status, text);
    } else {
        say(ui->status, P_("It could not be checked or installed."));
    }
}

static void on_installed(gaudit_run_status status, const GauditRunResult *result, gpointer data)
{
    VendorUi *ui = data;
    ended(ui, status, result);
    grey(ui->anyway);
    /* What the system has now: the Updates collection again. */
    if (status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_VENDOR
        && strcmp(result->vendor.result, "installed") == 0)
        recollect(NULL);
    ui_unref(ui);
}

static void install_now(VendorUi *ui, gboolean anyway)
{
    say(ui->status, P_("Installing… It needs administrator rights: use the switch beside the "
                       "title if asked."));
    g_autofree char *command = g_strdup_printf("run vendor-install %s%s", ui->id,
                                               anyway ? " anyway" : "");
    if (!gaudit_session_run(command, NULL, on_installed, ui_ref(ui))) {
        say(ui->status, P_("It is already under way."));
        ui_unref(ui);
    }
}

static void on_anyway(GtkButton *button, gpointer user_data)
{
    grey(GTK_WIDGET(button));
    install_now(user_data, TRUE);
}

static void on_verified(gaudit_run_status status, const GauditRunResult *result, gpointer data)
{
    VendorUi *ui = data;
    forget_download(ui);  /* the helper has its own copy, or none */
    const gaudit_vendor_package *p = gaudit_vendor_find(ui->id);
    const char *r = status == GAUDIT_RUN_OK && result != NULL && result->kind == GAUDIT_RESULT_VENDOR
                    ? result->vendor.result : NULL;
    if (r != NULL && strcmp(r, "verified") == 0) {
        install_now(ui, FALSE);
    } else if (r != NULL && strcmp(r, "weak") == 0 && p != NULL) {
        g_autofree char *text = g_strdup_printf(
            /* Translators: who makes it, then a hash method's name, e.g. SHA1. */
            P_("The package is signed by %s with the key the program knows for it, and every part "
               "of it matches the signature. But the signature uses %s, an older method that apt "
               "no longer accepts for software sources. Install it anyway, or go back."),
            p->vendor, result->vendor.hash[0] != '\0' ? result->vendor.hash : "?");
        say(ui->status, P_("Checked."));
        say(ui->weak, text);
        if (ui->anyway != NULL)
            gtk_widget_set_visible(ui->anyway, TRUE);
    } else {
        ended(ui, status, result);
    }
    ui_unref(ui);
}

typedef struct {
    VendorUi *ui;
    gaudit_update_download dl;
    gboolean got;
} DownloadRun;

static gboolean on_download_line(const char *line, gpointer user_data)
{
    DownloadRun *r = user_data;
    gaudit_update_download d;
    if (r->got || gaudit_update_parse_download(line, &d) != 0 || strcmp(d.id, r->ui->id) != 0) {
        g_debug("gaudit: vendor download: line refused: %s", line);
        return FALSE;
    }
    r->dl = d;
    r->got = TRUE;
    return TRUE;
}

static void on_downloaded(gboolean broken, gpointer user_data)
{
    DownloadRun *r = user_data;
    VendorUi *ui = r->ui;
    if (!broken && r->got && r->dl.status == 0
        && gaudit_vendor_verify_args_ok(ui->id, ui->version, r->dl.path)) {
        ui->download = g_strdup(r->dl.path);
        say(ui->status, P_("Downloaded. Checking the signature… It needs administrator rights: "
                           "use the switch beside the title if asked."));
        g_autofree char *command = g_strdup_printf("run vendor-verify %s %s %s", ui->id,
                                                   ui->version, r->dl.path);
        if (!gaudit_session_run(command, NULL, on_verified, ui_ref(ui))) {
            say(ui->status, P_("It is already under way."));
            forget_download(ui);
            ui_unref(ui);
        }
    } else {
        g_debug("gaudit: vendor download: broken=%d line=%d status=%d reason=%s path=%s version=%s",
                  broken, r->got, r->got ? r->dl.status : -1, r->got ? r->dl.reason : "",
                  r->got ? r->dl.path : "", ui->version);
        say(ui->status, P_("It could not be downloaded, so nothing was installed."));
    }
    ui_unref(ui);
    g_free(r);
}

static void on_install(GtkButton *button, gpointer user_data)
{
    VendorUi *ui = user_data;
    if (ui->version[0] == '\0')
        return;
    grey(GTK_WIDGET(button));
    say(ui->status, P_("Downloading…"));
    DownloadRun *r = g_new0(DownloadRun, 1);
    r->ui = ui_ref(ui);
    const char *args[] = { "updates", "download", ui->id, ui->version, NULL };
    gaudit_orchestrator_start(args, 35 * 60, FALSE, on_download_line, on_downloaded, r);
}

static GtkWidget *note_label(void)
{
    GtkWidget *l = gtk_label_new(NULL);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_set_visible(l, FALSE);
    return l;
}

/* A known vendor package: what it means that nothing updates it, and the
 * ways to keep it up to date, a software source first. Every name, address
 * and app id comes from gAudit's own table (vendor.h), never from the
 * package or the line; the version is shown as plain text. */
static AdwNavigationPage *vendor_page(const char *line, GPtrArray *lines)
{
    gaudit_update_vendor v;
    const gaudit_vendor_package *p;
    if (gaudit_update_parse_vendor(line, &v) != 0 || (p = gaudit_vendor_find(v.id)) == NULL)
        return NULL;
    /* Translators: %s is a program's name, e.g. "Zoom". */
    g_autofree char *title = g_strdup_printf(P_("Update %s Yourself"), p->title);
    g_autofree char *problem = g_strdup_printf(
        /* Translators: a program's name, its version, then who makes it. */
        P_("%s (version %s) is installed from a package %s offers only as a download, without a "
           "software source. So the system never updates it, not even with security fixes."),
        p->title, v.version[0] != '\0' ? v.version : "?", p->vendor);
    g_autofree char *source = g_strdup_printf(
        /* Translators: %s is who makes the program. */
        P_("Best is a software source: then the system updates it with everything else. Look for "
           "one from %s itself, or from someone you trust; the key of a source decides what is "
           "installed on this computer, so the choice is yours."), p->vendor);
    g_autofree char *download = g_strdup_printf(
        /* Translators: who makes it, then the address of their download page. */
        P_("Download new versions from %s's own page and install them: %s"), p->vendor, p->download);
    /* Who makes the Flatpak, when the table says (checked by hand). */
    g_autofree char *flatpak =
        p->flatpak == NULL ? g_strdup("")
        : p->flatpak_mark == GAUDIT_FLATPAK_VERIFIED ? g_strdup_printf(
            /* Translators: a Flatpak app id, then who makes the program. */
            P_("Or use it as a Flatpak instead (%s on Flathub), which gets updates. Flathub marks "
               "it “Verified”: %s makes it."), p->flatpak, p->vendor)
        : p->flatpak_mark == GAUDIT_FLATPAK_UNVERIFIED ? g_strdup_printf(
            /* Translators: a Flatpak app id, then who makes the program. */
            P_("Or use it as a Flatpak instead (%s on Flathub), which gets updates. Flathub marks "
               "it “Unverified”: someone other than %s makes it, so you trust them as well."),
            p->flatpak, p->vendor)
        : g_strdup_printf(
            /* Translators: a Flatpak app id, then who makes the program. */
            P_("Or use it as a Flatpak instead (%s on Flathub), which gets updates. On its page on "
               "Flathub, the mark “Verified” (a blue badge) means %s makes it; where the page "
               "says “Unverified”, or has no mark, someone else does."),
            p->flatpak, p->vendor);
    /* The vendor's own snap, when there is one (checked by hand). */
    g_autofree char *snap = p->snap == NULL ? g_strdup("") : g_strdup_printf(
        /* Translators: a snap's name, then who makes the program. */
        P_("Or use it as a snap instead (%s in the Snap Store), which gets updates. It is "
           "published by %s itself."), p->snap, p->vendor);
    /* The paragraphs that apply, one blank line between. */
    const char *parts[] = { source, download, snap, flatpak };
    GString *joined = g_string_new(NULL);
    for (gsize i = 0; i < G_N_ELEMENTS(parts); i++)
        if (parts[i][0] != '\0')
            g_string_append_printf(joined, "%s%s", joined->len > 0 ? "\n\n" : "", parts[i]);
    g_autofree char *how = g_string_free(joined, FALSE);
    AdwNavigationPage *page = gaudit_fix_page_new(
        title, problem, how, NULL,
        p->key_file != NULL
            ? P_("Looking for the newest version and installing it here is a fallback for a "
                 "package without a source: you chose this package, and there may be a good "
                 "reason for it.")
            : P_("Looking for the newest version here is a fallback for a package without a "
                 "source: you chose this package, and there may be a good reason for it."),
        NULL, NULL, NULL, NULL);
    GtkWidget *box = g_object_get_data(G_OBJECT(page), "gaudit-fix-box");
    GtkWidget *how_label = g_object_get_data(G_OBJECT(page), "gaudit-fix-how");
    if (p->latest == NULL || box == NULL || how_label == NULL)
        return page;

    VendorUi *ui = g_new0(VendorUi, 1);
    ui->ref = 1;
    g_strlcpy(ui->id, p->id, sizeof ui->id);
    g_object_set_data_full(G_OBJECT(page), "gaudit-vendor-ui", ui, ui_unref);

    /* A sequence, as in a dialog: the buttons at the end, the last one
     * shown the default; each goes grey once its step is over. */
    GtkWidget *check = gaudit_action_button_new(P_("Check for a New Version"), FALSE, TRUE);
    gtk_widget_set_halign(check, GTK_ALIGN_END);
    gtk_widget_set_tooltip_text(check, P_("Asks the maker's page which version is the newest. "
                                          "Nothing is downloaded or installed."));
    GtkWidget *latest = note_label();
    gtk_widget_add_css_class(latest, "dim-label");
    GtkWidget *install = gaudit_action_button_new(P_("Install"), FALSE, TRUE);
    gtk_widget_set_halign(install, GTK_ALIGN_END);
    gtk_widget_set_tooltip_text(install, P_("Downloads the newer version, checks its signature "
                                            "and installs it"));
    gtk_widget_set_visible(install, FALSE);
    GtkWidget *status = note_label();
    gtk_widget_add_css_class(status, "dim-label");
    GtkWidget *weak = note_label();
    GtkWidget *anyway = gaudit_action_button_new(P_("Install Anyway"), FALSE, TRUE);
    gtk_widget_set_halign(anyway, GTK_ALIGN_END);
    gtk_widget_set_visible(anyway, FALSE);
    weak_set(&ui->check, check);
    weak_set(&ui->latest, latest);
    weak_set(&ui->install, install);
    weak_set(&ui->status, status);
    weak_set(&ui->weak, weak);
    weak_set(&ui->anyway, anyway);

    g_signal_connect(check, "clicked", G_CALLBACK(on_check_latest), ui);
    g_signal_connect(install, "clicked", G_CALLBACK(on_install), ui);
    g_signal_connect(anyway, "clicked", G_CALLBACK(on_anyway), ui);
    GtkWidget *after = how_label;
    GtkWidget *order[] = { check, latest, install, status, weak, anyway };
    for (gsize i = 0; i < G_N_ELEMENTS(order); i++) {
        gtk_box_insert_child_after(GTK_BOX(box), order[i], after);
        after = order[i];
    }

    /* What this session found out already. */
    for (guint i = 0; lines != NULL && i < lines->len; i++) {
        gaudit_update_latest l;
        if (gaudit_update_parse_latest(g_ptr_array_index(lines, i), &l) == 0
            && strcmp(l.id, p->id) == 0 && l.status == 0)
            show_latest(ui, &l);
    }
    return page;
}

/* --- A local copy of a vendor's source ------------------------------------ */

static void on_show_previous(GtkButton *button, gpointer user_data)
{
    /* One step, as in a dialog: shown once, then the button is done. */
    gtk_widget_set_visible(GTK_WIDGET(user_data), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
}

/* Every name, address and release list comes from gAudit's own table
 * (vendor.h); the line gives only what the collection found. gAudit never
 * downloads or installs anything for it. */
static AdwNavigationPage *vendor_local_page(const char *line)
{
    gaudit_update_local l;
    const gaudit_vendor_local *v;
    if (gaudit_update_parse_local(line, &l) != 0 || (v = gaudit_vendor_local_find(l.id)) == NULL)
        return NULL;
    char made[32], running[32], previous[32];
    gaudit_vendor_release_name(l.made_for, made, sizeof made);
    gaudit_vendor_release_name(l.running, running, sizeof running);
    gaudit_vendor_release_name(l.previous, previous, sizeof previous);
    /* Translators: %s is a product, e.g. "CUDA". */
    g_autofree char *title = g_strdup_printf(P_("%s From a Local Copy"), v->title);
    g_autofree char *problem = g_strdup_printf(
        /* Translators: a product, its version, who makes it, the release the copy
         * was made for (e.g. "Ubuntu 26.04"), then a sentence about the packages. */
        P_("%s %s was installed from a local copy of %s's software source, made for %s. %s"),
        v->title, l.version, v->vendor, made,
        PN_("The copy never changes, so the package from it never gets updates, not even "
            "security fixes.",
            "The copy never changes, so the packages from it never get updates, not even "
            "security fixes.", l.packages));
    g_autofree char *other = l.running[0] != '\0' && strcmp(l.running, l.made_for) != 0
        /* Translators: the release the copy was made for, then the one running. */
        ? g_strdup_printf(P_("The copy was made for %s, not for %s, which this computer runs. The "
                             "program does not recommend using a source made for another release: "
                             "it was made and tested for that release, against the libraries it "
                             "has."), made, running)
        : g_strdup("");
    g_autofree char *how = NULL;
    gboolean offer_previous = FALSE;
    if (l.running[0] != '\0' && gaudit_vendor_local_has_network(v, l.running)) {
        g_autofree char *dashed = g_strdup(l.version);
        g_strdelimit(dashed, ".", '-');
        g_autofree char *package = v->versioned != NULL ? g_strconcat(v->versioned, dashed, NULL) : NULL;
        g_autofree char *stay = package == NULL ? g_strdup("") : g_strdup_printf(
            /* Translators: a version (13.3), then a package name (cuda-toolkit-13-3). */
            P_(" To stay on version %s, install the package %s: it keeps that version, and still "
               "gets its fixes."), l.version, package);
        how = g_strdup_printf(
            /* Translators: who makes it, the release running, who makes it, the release
             * running, the download page, the product, then the sentence about one version. */
            P_("%s has a software source for this release (%s). Set it up from %s's download "
               "page, choosing the network installer for %s: %s\n\nThe system then updates %s "
               "with everything else.%s"),
            v->vendor, running, v->vendor, running, v->download, v->title, stay);
    } else {
        how = g_strdup_printf(
            /* Translators: who makes it, the release running, who makes it, its download page. */
            P_("%s has no software source for this release (%s) yet. Look on %s's download page "
               "now and then: %s"),
            v->vendor, l.running[0] != '\0' ? running : "?", v->vendor, v->download);
        offer_previous = l.previous[0] != '\0' && gaudit_vendor_local_has_network(v, l.previous);
    }
    if (other[0] != '\0') {
        char *both = g_strconcat(how, "\n\n", other, NULL);
        g_free(how);
        how = both;
    }
    AdwNavigationPage *page = gaudit_fix_page_new(
        title, problem, how, NULL,
        P_("This is a recommendation: staying on a version can be deliberate, such as for a "
           "project that needs it. The program downloads and installs nothing for it."),
        NULL, NULL, NULL, NULL);
    GtkWidget *box = g_object_get_data(G_OBJECT(page), "gaudit-fix-box");
    GtkWidget *how_label = g_object_get_data(G_OBJECT(page), "gaudit-fix-how");
    if (!offer_previous || box == NULL || how_label == NULL)
        return page;
    /* Strict by default: the source for the release before only on an
     * explicit click, never stored, never further back. */
    /* Translators: %s is a release, e.g. "Ubuntu 26.04". */
    g_autofree char *label = g_strdup_printf(P_("Show the Source for %s"), previous);
    GtkWidget *button = gaudit_action_button_new(label, FALSE, TRUE);
    gtk_widget_set_halign(button, GTK_ALIGN_END);
    g_autofree char *text = g_strdup_printf(
        /* Translators: who makes it, the release before, who makes it, the release before. */
        P_("%s has a source for %s, the release before. Using a source made for an earlier release "
           "is not something the program recommends: it was made and tested for that release, "
           "against the libraries it has. If you choose it anyway, set it up from %s's download "
           "page, choosing %s."),
        v->vendor, previous, v->vendor, previous);
    GtkWidget *reveal = note_label();
    gtk_label_set_text(GTK_LABEL(reveal), text);
    g_signal_connect(button, "clicked", G_CALLBACK(on_show_previous), reveal);
    gtk_box_insert_child_after(GTK_BOX(box), button, how_label);
    gtk_box_insert_child_after(GTK_BOX(box), reveal, button);
    return page;
}

void gaudit_updates_clean_downloads(void)
{
    /* What a crash or a closed app left in ~/.cache/gaudit/vendor. */
    const char *home = g_get_home_dir();
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_dir != NULL)
        home = pw->pw_dir;
    g_autofree char *dir = g_build_filename(home, ".cache", "gaudit", "vendor", NULL);
    GDir *d = g_dir_open(dir, 0, NULL);
    if (d == NULL)
        return;
    const char *name;
    while ((name = g_dir_read_name(d)) != NULL) {
        g_autofree char *path = g_build_filename(dir, name, NULL);
        if (!g_file_test(path, G_FILE_TEST_IS_SYMLINK) && g_file_test(path, G_FILE_TEST_IS_REGULAR))
            g_unlink(path);
    }
    g_dir_close(d);
    g_rmdir(dir);
}

AdwNavigationPage *gaudit_updates_fix_page(const char *fix_id, GPtrArray *lines, guint item)
{
    gaudit_update_fact f;
    unsigned count;
    if (fix_id == NULL || lines == NULL || item >= lines->len)
        return NULL;
    const commands *cmd = commands_for(lines);

    if (strcmp(fix_id, "vendor") == 0)
        return vendor_page(g_ptr_array_index(lines, item), lines);
    if (strcmp(fix_id, "vendor-local") == 0)
        return vendor_local_page(g_ptr_array_index(lines, item));

    if (strcmp(fix_id, "reinstall") == 0) {
        /* One page for every changed or missing file: reinstalling puts the
         * packages' own files back. The names come from the helper's lines
         * in the cache, and only plain ones go into the command. */
        gaudit_run_event ev;
        if (gaudit_run_parse_line(g_ptr_array_index(lines, item), &ev) != 0
            || ev.type != GAUDIT_RUN_EVENT_INTEGRITY)
            return NULL;
        g_autoptr(GPtrArray) names = g_ptr_array_new_with_free_func(g_free);
        g_autoptr(GHashTable) seen = g_hash_table_new(g_str_hash, g_str_equal);
        gboolean left_out = FALSE;
        for (guint i = 0; i < lines->len; i++) {
            gaudit_run_event fe;
            if (gaudit_run_parse_line(g_ptr_array_index(lines, i), &fe) != 0
                || fe.type != GAUDIT_RUN_EVENT_INTEGRITY_FILE
                || fe.file.kind == GAUDIT_INTEGRITY_FILE_UNREADABLE)
                continue;
            if (!gaudit_apt_plain_package(fe.file.package) || names->len >= GAUDIT_APT_MAX_PACKAGES) {
                left_out = TRUE;
                continue;
            }
            char *name = g_strdup(fe.file.package);
            if (g_hash_table_add(seen, name))
                g_ptr_array_add(names, name);
            else
                g_free(name);
        }
        gboolean debian = cmd != NULL && strcmp(cmd->backend, "debian") == 0;
        unsigned long found = ev.integrity.changed + ev.integrity.missing;
        const char *problem = P_("Files installed by packages were changed or are gone. It may be "
                                 "harmless, such as a program changing its own file, but nothing "
                                 "should change installed files.");
        const char *note = ev.integrity.shown < found || left_out
            ? P_("Not every package is in the command: only those listed in the report, with "
                 "plain names. Check again afterwards to see what is left.")
            : P_("Afterwards, it is checked again: the files should then match.");
        AptStep a;
        if (debian && names->len > 0
            && apt_step(&a, "reinstall", (const char *const *)names->pdata, names->len))
            return gaudit_fix_page_new_steps(
                P_("Put the Package Files Back"), problem,
                P_("If you did not change them yourself, reinstall the packages: it puts their "
                   "own files back, and keeps your settings in /etc."),
                &a.step, 1, note, recollect, NULL, NULL);
        return gaudit_fix_page_new(P_("Put the Package Files Back"), problem,
                                   P_("If you did not change them yourself, reinstall the packages "
                                      "with your package manager."),
                                   NULL, note, NULL, NULL, NULL, NULL);
    }

    if (gaudit_update_parse_line(g_ptr_array_index(lines, item), &f, &count) != 1)
        return NULL;  /* every other fix is about a fact */

    /* Each row its own page, with only its group: one problem a page. */
    if (strcmp(fix_id, "sourceless") == 0 && f.key == GAUDIT_UPDATE_SOURCELESS_ABOVE)
        return gaudit_sourceless_page_new_group(GAUDIT_SOURCELESS_ABOVE_SOURCE);
    if (strcmp(fix_id, "sourceless") == 0 && f.key == GAUDIT_UPDATE_SOURCELESS_LEFTOVER)
        return gaudit_sourceless_page_new_group(GAUDIT_SOURCELESS_LEFTOVER);
    if (strcmp(fix_id, "sourceless") == 0 && f.key == GAUDIT_UPDATE_SOURCELESS_OTHER)
        return gaudit_sourceless_page_new_group(GAUDIT_SOURCELESS_OTHER_SOURCE);
    if (strcmp(fix_id, "sourceless") == 0 && f.key == GAUDIT_UPDATE_SOURCELESS_KEPT)
        return gaudit_sourceless_page_new_group(GAUDIT_SOURCELESS_KEPT);
    if (strcmp(fix_id, "sourceless") == 0 && f.key == GAUDIT_UPDATE_SOURCELESS)
        return gaudit_sourceless_page_new();  /* the groups could not be told apart */

    gboolean debian = cmd != NULL && strcmp(cmd->backend, "debian") == 0;
    AptStep steps[2];

    if (strcmp(fix_id, "check-on") == 0 && f.key == GAUDIT_UPDATE_CHECK_DAYS && debian
        && apt_step(&steps[0], "apt-update", NULL, 0))
        return gaudit_fix_page_new_steps(
            P_("Look for Updates"),
            P_("This computer never looks for updates, so it never finds security updates either."),
            P_("In your system's settings for software updates, choose to look for updates every "
               "day. Until then, you can look once yourself."),
            &steps[0].step, 1,
            P_("Looking once is not enough: updates come out all the time."),
            recollect, NULL, NULL);

    if (strcmp(fix_id, "check-on") == 0 && f.key == GAUDIT_UPDATE_CHECK_DAYS)
        return gaudit_fix_page_new(
            P_("Look for Updates"),
            P_("This computer never looks for updates, so it never finds security updates either."),
            P_("In your system's settings for software updates, choose to look for updates every "
               "day. Until then, you can look once yourself with this command in a terminal."),
            cmd != NULL ? cmd->look : NULL,
            P_("Looking once is not enough: updates come out all the time."),
            NULL, NULL, NULL, NULL);

    if (strcmp(fix_id, "automatic-on") == 0 && f.key == GAUDIT_UPDATE_INSTALL)
        return automatic_page(lines, f.status == GAUDIT_FACT_KNOWN && f.value == 1, cmd);

    if (strcmp(fix_id, "timers") == 0 && debian
        && (f.key == GAUDIT_UPDATE_CHECK_TIMER || f.key == GAUDIT_UPDATE_INSTALL_TIMER)
        && apt_step(&steps[0], "enable-apt-timers", NULL, 0))
        return gaudit_fix_page_new_steps(
            P_("Switch On the Daily Jobs"),
            P_("The jobs that look for and install updates every day are switched off, so the "
               "settings for updates have no effect."),
            P_("Switch them on again:"),
            &steps[0].step, 1,
            P_("Afterwards, it is checked again: the jobs should then be listed as on."),
            recollect, NULL, NULL);

    if (strcmp(fix_id, "timers") == 0
        && (f.key == GAUDIT_UPDATE_CHECK_TIMER || f.key == GAUDIT_UPDATE_INSTALL_TIMER))
        return gaudit_fix_page_new(
            P_("Switch On the Daily Jobs"),
            P_("The jobs that look for and install updates every day are switched off, so the "
               "settings for updates have no effect."),
            P_("Run this command in a terminal to switch them on again."),
            cmd != NULL ? cmd->timers : NULL,
            P_("Afterwards, check again: the jobs should then be listed as on."),
            NULL, NULL, NULL, NULL);

    if (strcmp(fix_id, "upgrade-off") == 0 && f.key == GAUDIT_UPDATE_UPGRADE_OFF) {
        g_autofree char *problem = g_strdup_printf(
            /* Translators: %s is one or more sources, e.g. "ppa:cappelikan/ppa". */
            P_("These software sources were switched off when the release was upgraded: %s. "
               "Nothing from them gets updates while they are off."), f.text[0] != '\0' ? f.text : "?");
        const char *why = P_("The upgrade switches off sources it does not know, since they may "
                             "not have packages for the new release yet; switching one on then "
                             "gives an error the next time updates are looked for.");
        /* A PPA can be set up again for this release with one command,
         * which the helper runs only for a PPA the upgrade switched off. */
        AptStep ppa[4];
        GauditFixStep ppa_steps[4];
        gsize n_ppa = 0;
        if (debian && g_file_test("/usr/bin/add-apt-repository", G_FILE_TEST_IS_EXECUTABLE)) {
            g_auto(GStrv) names = g_strsplit(f.text, ", ", -1);
            for (gsize i = 0; names[i] != NULL && n_ppa < G_N_ELEMENTS(ppa); i++) {
                if (!gaudit_apt_plain_ppa(names[i]))
                    continue;
                AptStep *a = &ppa[n_ppa];
                g_strlcpy(a->arg, names[i], sizeof a->arg);
                const char *args[] = { a->arg };
                if (!apt_step(a, "add-ppa", args, 1))
                    continue;
                ppa_steps[n_ppa] = a->step;
                n_ppa++;
            }
        }
        if (n_ppa > 0) {
            g_autofree char *how = g_strconcat(
                why, " ",
                P_("Check the PPA's page on Launchpad first for packages for this release. If it "
                   "has them, set it up again here. Other sources are switched on in your "
                   "system's settings for software sources."), NULL);
            return gaudit_fix_page_new_steps(
                P_("Software Sources Switched Off"), problem, how, ppa_steps, n_ppa,
                P_("Only the PPA's own page can tell whether it is ready: on Launchpad, it must list "
                   "packages for exactly this release. Packages for older releases are not enough, "
                   "and neither is this release in the list without packages, so look there "
                   "before you run the command."),
                recollect, NULL, NULL);
        }
        g_autofree char *how = g_strconcat(
            why, " ",
            P_("Check the source's page first (for a PPA, its page on Launchpad) for packages for "
               "this release. If it has them, switch it on in your system's settings for "
               "software sources."), NULL);
        return gaudit_fix_page_new(
            P_("Software Sources Switched Off"), problem, how, NULL,
            P_("The program does not switch them on: only the source's own page can tell whether "
               "it is ready for this release."),
            NULL, NULL, NULL, NULL);
    }

    if (strcmp(fix_id, "unread-sources") == 0 && f.key == GAUDIT_UPDATE_UNREAD_SOURCES) {
        g_autofree char *problem = g_strdup_printf(
            /* Translators: %s is one or more host names, e.g. "prerelease.keybase.io". */
            P_("The software source %s is set up, but its lists of packages have never been "
               "fetched, so nothing from it gets updates."), f.text[0] != '\0' ? f.text : "?");
        const char *how = P_("Look for updates: that fetches the lists from every source. If it "
                             "still cannot be read, the command shows why, often a signing key "
                             "that is missing or has expired, or a source that no longer exists.");
        const char *note = P_("It often happens after an upgrade of the release, or when a source is "
                              "added without looking for updates since.");
        if (debian && apt_step(&steps[0], "apt-update", NULL, 0))
            return gaudit_fix_page_new_steps(P_("Read the Software Source"), problem, how,
                                             &steps[0].step, 1, note, recollect, NULL, NULL);
        return gaudit_fix_page_new(P_("Read the Software Source"), problem, how,
                                   cmd != NULL ? cmd->look : NULL, note, NULL, NULL, NULL, NULL);
    }

    if (strcmp(fix_id, "look-now") == 0 && f.key == GAUDIT_UPDATE_INDEX_AGE && debian
        && apt_step(&steps[0], "apt-update", NULL, 0))
        return gaudit_fix_page_new_steps(
            P_("Look for Updates Now"),
            P_("This computer has not looked for updates for a long time, so it does not know "
               "about updates published since."),
            P_("Look for them now. If it keeps happening, check that the computer looks for "
               "updates by itself."),
            &steps[0].step, 1, NULL, recollect, NULL, NULL);

    if (strcmp(fix_id, "look-now") == 0 && f.key == GAUDIT_UPDATE_INDEX_AGE)
        return gaudit_fix_page_new(
            P_("Look for Updates Now"),
            P_("This computer has not looked for updates for a long time, so it does not know "
               "about updates published since."),
            cmd != NULL && cmd->look != NULL
                ? P_("Run this command in a terminal. If it keeps happening, check that the "
                     "computer looks for updates by itself.")
                : P_("Install the updates with the command below; it looks for new ones first."),
            cmd != NULL ? (cmd->look != NULL ? cmd->look : cmd->install) : NULL,
            NULL, NULL, NULL, NULL, NULL);

    if (strcmp(fix_id, "install-now") == 0 && debian
        && (f.key == GAUDIT_UPDATE_PENDING_SECURITY || f.key == GAUDIT_UPDATE_PENDING)) {
        /* One command where apt can fetch the lists itself, else two steps. */
        gsize n = 0;
        if (upgrade_updates(lines))
            n = apt_step(&steps[0], "apt-upgrade-update", NULL, 0) ? 1 : 0;
        else if (apt_step(&steps[0], "apt-update", NULL, 0) && apt_step(&steps[1], "apt-upgrade", NULL, 0))
            n = 2;
        GauditFixStep s2[2];
        for (gsize i = 0; i < n; i++)
            s2[i] = steps[i].step;
        if (n > 0)
            return gaudit_fix_page_new_steps(
                P_("Install the Updates"),
                f.key == GAUDIT_UPDATE_PENDING_SECURITY
                    ? P_("Security updates are waiting. Until they are installed, the problems they "
                         "fix stay open on this computer.")
                    : P_("Updates are waiting, and some of them may be security updates."),
                P_("Install them with your system's software updater, or here:"),
                s2, n,
                P_("Installing updates automatically keeps this from building up again."),
                recollect, NULL, NULL);
    }

    if (strcmp(fix_id, "install-now") == 0
        && (f.key == GAUDIT_UPDATE_PENDING_SECURITY || f.key == GAUDIT_UPDATE_PENDING))
        return gaudit_fix_page_new(
            P_("Install the Updates"),
            f.key == GAUDIT_UPDATE_PENDING_SECURITY
                ? P_("Security updates are waiting. Until they are installed, the problems they fix "
                     "stay open on this computer.")
                : P_("Updates are waiting, and some of them may be security updates."),
            P_("Install them with your system's software updater, or run this command in a "
               "terminal."),
            cmd != NULL ? cmd->install : NULL,
            P_("Installing updates automatically keeps this from building up again."),
            NULL, NULL, NULL, NULL);

    if (strcmp(fix_id, "mirror") == 0 && f.key == GAUDIT_UPDATE_SECURITY_MIRROR) {
        g_autofree char *problem = g_strdup_printf(
            /* Translators: %s is a host name, e.g. no.archive.ubuntu.com. */
            P_("Security updates come from %s, a mirror. A mirror may lag behind, and security "
               "updates should not wait."), f.text[0] != '\0' ? f.text : "?");
        return gaudit_fix_page_new(
            P_("Get Security Updates from the Source"), problem,
            P_("In your system's settings for software sources, let security updates come from "
               "the distribution's own server. Mirrors are fine for the other updates."),
            NULL, NULL, NULL, NULL, NULL, NULL);
    }

    if (strcmp(fix_id, "other-systems") == 0 && f.key == GAUDIT_UPDATE_OTHER_SYSTEMS) {
        g_autofree char *problem = g_strdup_printf(
            /* Translators: %s is a list of package systems, e.g. "rpm, Nix". */
            P_("Packages managed by %s are on this computer. The program does not check them, so "
               "it cannot tell whether they get updates."), f.text[0] != '\0' ? f.text : "?");
        return gaudit_fix_page_new(
            P_("Other Package Systems"), problem,
            P_("Keep them up to date with their own tools. If they are left over and nothing uses "
               "them any more, they still need updates as long as they are installed."),
            NULL, NULL, NULL, NULL, NULL, NULL);
    }
    return NULL;  /* not a fix this fact can have */
}
