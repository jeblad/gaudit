/* SPDX-License-Identifier: GPL-3.0-only */
/* The public share folder: the one place a desktop following XDG means for
 * what may be shared openly on the local network (XDG_PUBLICSHARE_DIR,
 * ~/Public in English), and other folders in the home folder with a name
 * it could have had, which can make it unclear which one is shared.
 *
 * Its name depends on the language of the first login and may be kept when
 * the language changes, so the names looked for are every name the
 * project knows (xdg-public-names.h) and every name the catalogs installed
 * on the machine give it (xdg-user-dirs.mo, read directly). Reads only;
 * never follows a link when listing. Plain C, for the collection. */
#pragma once

#include <stddef.h>

#define GAUDIT_PUBLIC_MAX_FOUND 32

typedef enum {
    GAUDIT_PUBLIC_CONFIG_NONE = 0,   /* no user-dirs.dirs, or it does not name it */
    GAUDIT_PUBLIC_CONFIG_SET,        /* it names a folder */
    GAUDIT_PUBLIC_CONFIG_DISABLED,   /* it names the home folder itself: switched off */
    GAUDIT_PUBLIC_CONFIG_UNKNOWN,    /* it could not be read, or not in the form xdg-user-dirs writes */
} gaudit_public_config;

typedef struct {
    char name[256];        /* the folder's name in the home folder */
    char lang[32];         /* a language the name belongs to ("" English, or not known) */
    int from_machine;      /* the name came from a catalog installed here */
    int current_name;      /* some translation still gives this name today */
    int is_standard;       /* it is the folder user-dirs.dirs names */
    int symlink;           /* it is a symbolic link */
    char link_target[512]; /* ... and where it leads, as written */
    int case_differs;      /* matched only when case is ignored (ASCII) */
    long entries;          /* what is in it, counted up to 1000 (1000: that many or more);
                              -1 could not be read; 0 for a link */
} gaudit_public_folder;

typedef struct {
    gaudit_public_config config;
    char standard[512];          /* CONFIG_SET: the folder it names, absolute */
    int standard_exists;         /* ... and it is there, as a folder */
    char system_default[256];    /* /etc/xdg/user-dirs.defaults' PUBLICSHARE, "" for none */
    char locale[64];             /* user-dirs.locale: the language the names were made in */
    unsigned names;              /* how many names were looked for */
    gaudit_public_folder found[GAUDIT_PUBLIC_MAX_FOUND];  /* in the home folder, the standard one too */
    unsigned n_found;
    int more;                    /* more were found than listed */
} gaudit_public_share;

/* Where to look; every path may be NULL for the usual place (tests give
 * their own). locale_dirs: NULL-terminated, folders holding
 * <lang>/LC_MESSAGES/xdg-user-dirs.mo. */
typedef struct {
    const char *home;
    const char *user_dirs;       /* default <home>/.config/user-dirs.dirs */
    const char *user_locale;     /* default <home>/.config/user-dirs.locale */
    const char *system_defaults; /* default /etc/xdg/user-dirs.defaults */
    const char *const *locale_dirs;  /* default /usr/share/locale, /usr/share/locale-langpack */
} gaudit_public_where;

/* 0 when the home folder could be read, -1 otherwise. */
int gaudit_public_share_find(const gaudit_public_where *where, gaudit_public_share *out);

/* --- Tidying up the structure (John, 2026-11-19) -------------------------------
 *
 * Only the structure is tidied: what is in a duplicate is moved into the
 * folder in use, never overwriting, and a folder is removed only when it
 * is empty. Files are never deleted; a user who wants that is told to do
 * it themselves. Both work on folders straight in the home folder, by
 * name (one component), the user's own, never through a link, as the
 * user. */

#define GAUDIT_PUBLIC_MAX_CLASHES 16

typedef struct {
    unsigned moved;                 /* entries moved over */
    unsigned clashes;               /* left: the folder in use has one of that name */
    char clash[GAUDIT_PUBLIC_MAX_CLASHES][256];  /* the first of them */
    unsigned other_disk;            /* left: on another filesystem (never copied) */
    unsigned failed;                /* left for another reason */
} gaudit_public_merge_result;

/* What moving everything in <home>/<from> into <home>/<to> would do,
 * changing nothing: moved counts what can go, clashes the names already in
 * <to>, other_disk what is on another filesystem. 0 when all can go, 1
 * when something stands in the way, -1 refused (not plain names, the same
 * folder, not the user's, a link). */
int gaudit_public_merge_check(const char *home, const char *from, const char *to,
                              gaudit_public_merge_result *r);

/* Moves everything in <home>/<from> into <home>/<to>, each entry as it is
 * (a folder with all in it), only when the check finds nothing in the way:
 * otherwise nothing is moved and the result says why (1), so a merge is
 * never left half done. Each move still never replaces anything
 * (RENAME_NOREPLACE), should something appear in between. 0 when all
 * moved, 1 nothing moved or some left, -1 refused. */
int gaudit_public_merge(const char *home, const char *from, const char *to,
                        gaudit_public_merge_result *r);

/* Removes <home>/<name> when it is an empty folder of the user's, not a
 * link. 0 removed, 1 not empty (nothing done), -1 refused or failed. */
int gaudit_public_remove_empty(const char *home, const char *name);

/* --- Services that share folders --------------------------------------------
 *
 * Before anything is moved: what shares a folder, read as the user from
 * files and /proc only. Samba (its shares in smb.conf, [homes] as the home
 * folder, and the usershares the file managers' one-click sharing makes,
 * in smb.conf's "usershare path", by default /var/lib/samba/usershares),
 * and GNOME Sharing (gnome-user-share, which always shares the public
 * folder) when it runs as the user. */

#define GAUDIT_SHARE_MAX 32

typedef enum {
    GAUDIT_SHARE_SAMBA = 0,          /* a share in smb.conf */
    GAUDIT_SHARE_SAMBA_USER,         /* a usershare */
    GAUDIT_SHARE_GNOME,              /* gnome-user-share, running */
} gaudit_share_kind;

typedef struct {
    gaudit_share_kind kind;
    char name[128];   /* the share's name; the program for GNOME */
    char path[512];   /* what it shares, absolute */
} gaudit_share_service;

typedef struct {
    gaudit_share_service s[GAUDIT_SHARE_MAX];
    unsigned n;
    int more;
    int usershares_unreadable;  /* the usershare folder is there, but not readable by the user */
} gaudit_share_services;

typedef struct {
    const char *home;
    const char *publicshare;  /* the public folder in use, or NULL */
    const char *smb_conf;     /* default /etc/samba/smb.conf */
    const char *proc;         /* default /proc */
    unsigned uid;
} gaudit_share_where;

void gaudit_share_services_find(const gaudit_share_where *where, gaudit_share_services *out);

/* Whether path is folder or inside it (both absolute, no trailing '/'). */
int gaudit_path_within(const char *path, const char *folder);

/* The translation of msgid in a .mo catalog's bytes (no context, the first
 * form of a plural), copied into out. 0 found, -1 not there or not a
 * well-formed catalog. Exposed for tests. */
int gaudit_mo_lookup(const unsigned char *data, size_t len, const char *msgid, char *out,
                     size_t out_len);

/* XDG_PUBLICSHARE_DIR from user-dirs.dirs' text, in the form xdg-user-dirs
 * writes ("$HOME/name" or "/absolute", backslash escapes), resolved
 * against home into out. Exposed for tests. */
gaudit_public_config gaudit_public_parse_user_dirs(const char *text, const char *home, char *out,
                                                   size_t out_len);
