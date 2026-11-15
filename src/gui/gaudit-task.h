/* SPDX-License-Identifier: GPL-3.0-only */
/* Task registry: one entry per sidebar item (Home excluded). */
#pragma once

#include <adwaita.h>
#include <glib.h>

#include "gaudit/backend.h"

G_BEGIN_DECLS

/* Home's report levels; each includes everything the ones below show. */
enum { GAUDIT_LEVEL_QUICK = 0, GAUDIT_LEVEL_NORMAL, GAUDIT_LEVEL_THOROUGH, GAUDIT_LEVEL_COUNT };

/* Only on/off parameters for now. Strings are N_()-marked; translate at use. */
typedef struct {
    const char *id;
    const char *title;
    const char *subtitle;
    gboolean default_value;
} GauditTaskParam;

typedef struct {
    const char *id;
    const char *title;
    const char *summary;   /* one sentence */
    const char *details;   /* longer explanation for non-technical users: what it does */
    const char *why;       /* why it matters to the user, N_() */
    const char *about_parameters;  /* page 0 opened from Parameters: what they do, N_() */
    const char *about_report;      /* page 0 opened from a report: what it shows, N_() */
    const char *icon;
    const char *const *capabilities;  /* NULL-terminated, resolved by the backend */
    const GauditTaskParam *params;
    gsize n_params;
    const char *run_command;  /* the orchestrator session's command for a run */
    const char *home_probe;   /* id of the Home row that leads here (e.g. "status.firewall"),
                                 which then stands for the task on Home; NULL for none */
    const char *home_tooltip; /* for the button on that row, N_()-marked */
    guint home_level;         /* a check run in the helper: the Home report level it runs
                                 at (GAUDIT_LEVEL_NORMAL, _THOROUGH); 0: not on Home */
    /* A plugin that collects for its rule script: its collection command
     * per Home report level (NULL where it has none), e.g. [QUICK]
     * "user secrets quick". run_command is then its full collection. */
    const char *home_commands[GAUDIT_LEVEL_COUNT];
    const char *home_title;   /* that row's title, N_()-marked */
    /* A plugin whose run is a collection for its rule script (run_command
     * "user <mode>"): checks one line of the collection strictly, and says
     * whether it is the last. NULL for runs that give a result directly. */
    gboolean (*collection_line)(const char *line, gboolean *last);
    const char *text_domain;  /* the plugin's own, for its report and fix pages */
    gboolean param_folders;   /* takes folders to search besides the home folder */
    gboolean param_read_limit;  /* takes the size up to which files are read */
    gboolean param_caches;    /* takes whether caches are searched too */
    /* The page for a fix a report row names: item is the position of the
     * collection line it is about, in lines (the validated cache). NULL: no
     * fixes. */
    AdwNavigationPage *(*fix_page)(const char *fix_id, GPtrArray *lines, guint item);
    const char *backend;      /* only with this package backend (e.g. "debian"); NULL: any */
    /* The helper parts of its commands ("user ... then run ...") only with
     * this package backend; elsewhere they are left out, and the commands
     * run as the user alone. NULL: everywhere. */
    const char *helper_backend;
    const char *run_waiting;  /* page 2 while the password is asked for, N_()-marked */
    const char *run_running;  /* page 2 while the check runs, N_()-marked */
} GauditTaskInfo;

/* The tasks for this system: those whose backend matches the one in use.
 * Indexes into this array are stable for the life of the process. */
const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks);

/* The command task runs for Home at level: its own command for the
 * nearest level at or below it (the fallback), or NULL when it has no
 * report on Home at that level. */
const char *gaudit_task_home_command(const GauditTaskInfo *task, guint level);

/* Whether a run command needs administrator rights (the password): it
 * runs in the helper ("run ..."), or has a helper part ("user ... then
 * run ..."). Decided by the command, so a plugin's levels may differ. */
gboolean gaudit_command_needs_admin(const char *command);

/* Whether task's Home report at level needs the password (FALSE when it
 * has none there). */
gboolean gaudit_task_home_needs_admin(const GauditTaskInfo *task, guint level);

/* The lowest level task has a Home report at; GAUDIT_LEVEL_COUNT for none. */
guint gaudit_task_home_from(const GauditTaskInfo *task);

/* The task with this id on this system, or NULL. */
const GauditTaskInfo *gaudit_task_by_id(const char *id);

/* The task that runs command (its own or a Home one), with its index; NULL
 * for none. */
const GauditTaskInfo *gaudit_task_for_command(const char *command, gsize *index);

/* The task's parameters for its full run (report "full"), or NULL when
 * the schema is missing. */
GSettings *gaudit_task_settings(const GauditTaskInfo *task);

/* The folders the task searches besides the home folder (param_folders):
 * those the user added (kept in its settings), then the file manager's
 * places outside the home folder (bookmarks, KDE places, /mnt/<user> when
 * it is the user's, mounted disks and network folders) the user has not
 * taken off the list. Places under the
 * home folder are searched with it anyway. All checked: absolute,
 * printable, no "..", existing folders, at most GAUDIT_TASK_MAX_FOLDERS.
 * Never NULL. places (may be NULL) gets which of them are places. */
#define GAUDIT_TASK_MAX_FOLDERS 15
GStrv gaudit_task_folders(const GauditTaskInfo *task);
GStrv gaudit_task_folders_split(const GauditTaskInfo *task, GStrv *places);

/* The sizes the read limit may be, smallest first; the smallest still holds
 * every real key file. */
#define GAUDIT_TASK_READ_LIMITS { 16384, 65536, 262144, 1048576 }
#define GAUDIT_TASK_READ_LIMIT_DEFAULT 65536

/* The task's read limit as kept in its settings, checked against the list
 * (the default otherwise). */
guint gaudit_task_read_limit(const GauditTaskInfo *task);
void gaudit_task_set_read_limit(const GauditTaskInfo *task, guint bytes);

/* Every parameter back to its default; the generated ones (the file
 * manager's places) made again, none taken off the list. */
void gaudit_task_reset_parameters(const GauditTaskInfo *task);

/* Whether caches are searched too (default no). */
gboolean gaudit_task_with_caches(const GauditTaskInfo *task);
void gaudit_task_set_with_caches(const GauditTaskInfo *task, gboolean on);

/* The full run's parameters as arguments: caches, the read limit (when
 * the task takes them), then the folders. Never NULL. */
GStrv gaudit_task_run_args(const GauditTaskInfo *task);

/* Adds a folder (and gives back a place taken off before), or takes one
 * off: a folder the user added is forgotten, a place is remembered as
 * removed. */
/* FALSE when the folder is not taken: under the home folder (searched with
 * it already) or not a plain absolute path. */
gboolean gaudit_task_add_folder(const GauditTaskInfo *task, const char *folder);
void gaudit_task_remove_folder(const GauditTaskInfo *task, const char *folder);

/* Packages needed by the task that are not installed.
 * Empty array: everything is in place. NULL: the task is not supported on
 * this distro. Only for presentation — the helper re-checks everything. */
GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg);

G_END_DECLS
