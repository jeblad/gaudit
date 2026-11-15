/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n-lib.h>
#include <string.h>

#include "gaudit-updates.h"
#include "gaudit-sourceless-page.h"
#include "gaudit-task-page.h"
#include "gaudit-session.h"
#include "gaudit-task.h"
#include "updates.h"
#include "apt-ops.h"
#include "gaudit-report-run.h"
#include "gaudit/run.h"

/* The plugin's own texts. */
#define P_(s) g_dgettext(GAUDIT_UPDATES_DOMAIN, s)

gboolean gaudit_updates_line(const char *line, gboolean *last)
{
    gaudit_update_fact f;
    unsigned count;
    int kind = gaudit_update_parse_line(line, &f, &count);
    *last = kind == 2;
    if (kind == 1 || kind == 2)
        return TRUE;
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
    a->step = (GauditFixStep){ a->shown, (const char *const *)a->run, a->explain };
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
        P_("Writes gAudit's own file /etc/apt/apt.conf.d/52gaudit-automatic-updates: this "
           "computer then looks for updates every day and installs them as unattended-upgrades "
           "is set up (on Debian and Ubuntu: security updates). It can be removed again here."),
        "run automatic-updates-on",
    };
    GauditConfAction u = {
        P_("Remove gAudit's Setting"),
        P_("Removes gAudit's own file /etc/apt/apt.conf.d/52gaudit-automatic-updates, if it is "
           "still as gAudit wrote it. Settings made elsewhere are not touched."),
        "run automatic-updates-remove",
    };
    /* Set up by gAudit: its own setting, which it can take away again;
     * once taken away, it can be switched on here again. */
    if (debian && on && mine)
        return gaudit_fix_page_new_conf(
            P_("Install Updates Automatically"),
            P_("gAudit has set this computer up to install updates by itself."),
            P_("It is gAudit's own setting, and it can be taken away again here. Then the "
               "computer's other settings decide."),
            NULL, &a, &u, TRUE, recollect, NULL, NULL);
    if (debian && have_tools && tools.value == 0)
        return gaudit_fix_page_new_conf(
            P_("Install Updates Automatically"),
            P_("Updates are not installed by themselves on this computer, so it is only as up to "
               "date as the last time someone installed them."),
            P_("gAudit can switch it on with a setting of its own: security updates are then "
               "installed by themselves. You are asked to confirm first, and it can be taken "
               "away again here."),
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
AdwNavigationPage *gaudit_updates_fix_page(const char *fix_id, GPtrArray *lines, guint item)
{
    gaudit_update_fact f;
    unsigned count;
    if (fix_id == NULL || lines == NULL || item >= lines->len)
        return NULL;
    const commands *cmd = commands_for(lines);

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

    if (strcmp(fix_id, "sourceless") == 0 && f.key >= GAUDIT_UPDATE_SOURCELESS
        && f.key <= GAUDIT_UPDATE_SOURCELESS_OTHER)
        return gaudit_sourceless_page_new();  /* the packages, listed */

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
            P_("Packages managed by %s are on this computer. gAudit does not check them, so it "
               "cannot tell whether they get updates."), f.text[0] != '\0' ? f.text : "?");
        return gaudit_fix_page_new(
            P_("Other Package Systems"), problem,
            P_("Keep them up to date with their own tools. If they are left over and nothing uses "
               "them any more, they still need updates as long as they are installed."),
            NULL, NULL, NULL, NULL, NULL, NULL);
    }
    return NULL;  /* not a fix this fact can have */
}
