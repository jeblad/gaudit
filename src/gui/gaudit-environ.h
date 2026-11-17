/* SPDX-License-Identifier: GPL-3.0-only */
/* The GUI's own environment. Its children get an empty one, but the GUI
 * itself starts with whatever the desktop gives it, and some variables
 * make a program load code it would not otherwise (LD_PRELOAD,
 * GTK_MODULES, GIO_EXTRA_MODULES ...). gAudit starts itself again without
 * them, before GTK is loaded, and says so on Home. Plain C, no GLib, so it
 * runs before anything else. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

/* 1 when an environment entry ("NAME=value") is one gAudit removes. */
int gaudit_environ_unwanted(const char *entry);

/* At the very start of main: when any unwanted variable is set, starts the
 * program again (/proc/self/exe, the same arguments) without them, telling
 * the new start which they were and their values; does not return then.
 * Otherwise returns, and remembers what an earlier start removed. */
void gaudit_environ_clean(char *argv[]);

/* The names an earlier start removed, ", " between, or NULL for none. */
const char *gaudit_environ_removed(void);

/* The variables it removed, each "NAME=value" (the value cut at 4 KiB),
 * as data from the caller: at most GAUDIT_ENVIRON_MAX. */
#define GAUDIT_ENVIRON_MAX 32
size_t gaudit_environ_removed_count(void);
const char *gaudit_environ_removed_entry(size_t i);

/* --- What a removed variable pointed to ------------------------------------ */

typedef enum {
    GAUDIT_ENV_PATHS,     /* a list of folders or files, ':' between (LD_PRELOAD: ' ' too) */
    GAUDIT_ENV_MODULES,   /* names of modules, looked up in the system's folders; one
                             with a '/' is a path */
    GAUDIT_ENV_OTHER,     /* changes how programs load or run, loads no code itself
                             (LD_DEBUG, GTK_DEBUG, GSETTINGS_BACKEND ...) */
} gaudit_env_kind;

gaudit_env_kind gaudit_environ_kind(const char *name);

/* Who besides the administrator can change a path, or what it leads to. */
typedef enum {
    GAUDIT_ENV_ROOT_ONLY = 0,   /* every folder on the way is root's, and only root writes it */
    GAUDIT_ENV_OWNER,           /* a folder (or the file) on the way belongs to another account */
    GAUDIT_ENV_GROUP,           /* ... can be written by a group that has members */
    GAUDIT_ENV_OTHERS,          /* ... can be written by every account */
    GAUDIT_ENV_EMPTY,           /* an empty entry (a ':' first, last or twice): the folder the
                                   program is started in */
    GAUDIT_ENV_RELATIVE,        /* not a full path: found from the folder it is started in */
} gaudit_env_reach;

typedef struct {
    gaudit_env_reach reach;
    char where[512];    /* the folder or file that decides it */
    uid_t owner;        /* OWNER: its owner */
    gid_t group;        /* GROUP: the group */
} gaudit_env_judgement;

/* Judges one path: from '/' down, every folder on the way and the path
 * itself (or, when it does not exist, the folders that do), both as
 * written and where its links really lead. A group counts only when it is
 * not root's and has members (as its own or as a primary group): a group
 * nobody is in can only be joined by root. */
void gaudit_environ_judge_path(const char *path, gaudit_env_judgement *out);

/* The members of a group, ", " between ("" for none), into buf. */
void gaudit_environ_group_members(gid_t group, char *buf, size_t len);
