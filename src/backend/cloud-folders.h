/* SPDX-License-Identifier: GPL-3.0-only */
/* Cloud folders: which file synchronisation clients are set up, and where
 * their folders are, found as the user from their own files, /proc and
 * known places only, never by running them. Only what the project's table
 * knows (AGENTS.md, the cloud plugin): Dropbox, Nextcloud, ownCloud,
 * MEGAsync, pCloud, Tresorit, the onedrive client, Insync, Jottacloud's
 * jotta-cli and rclone. Of rclone only each remote's name and type are
 * read (and a crypt remote's "remote"), never anything else in its
 * section, which holds tokens and passwords. Also the gathering folder
 * (~/Cloud, ~/SkyTjenester), and whether each folder is under it.
 * Plain C, for the collection. */
#pragma once

#define GAUDIT_CLOUD_MAX 48

typedef enum {
    GAUDIT_CLOUD_FOLDER = 0,   /* the client's own settings name the folder */
    GAUDIT_CLOUD_DEFAULT,      /* the client's default folder is there; its settings
                                  cannot be read, so it may not be the one it uses */
    GAUDIT_CLOUD_INSTALLED,    /* the client is installed; where its folder is cannot be seen */
    GAUDIT_CLOUD_MOUNT,        /* mounted (pCloud, rclone mount) */
    GAUDIT_CLOUD_SETUP,        /* set up, with no folder of its own (an rclone remote) */
} gaudit_cloud_how;

typedef struct {
    char client[16];    /* dropbox, nextcloud, owncloud, megasync, pcloud, tresorit,
                           onedrive, insync, jotta-cli, rclone */
    char service[16];   /* dropbox, nextcloud, owncloud, mega, pcloud, tresorit, onedrive,
                           google-drive, jottacloud, proton-drive, webdav */
    gaudit_cloud_how how;
    char path[512];     /* the folder or mount point, absolute; "" for none */
    char name[128];     /* an rclone remote's name, an Insync account; "" for none */
    int encrypted;      /* an rclone crypt remote over it: encrypted before it leaves */
    char via[128];      /* ... that crypt remote's name, "" for none */
    int gathered;       /* the folder is under the gathering folder */
} gaudit_cloud_finding;

/* A systemd user unit that mounts an rclone remote (rclone-*.service, as
 * the cloud plugin makes them, or any of that name that runs rclone mount). */
#define GAUDIT_CLOUD_MAX_UNITS 16
typedef struct {
    char file[64];      /* its file name */
    char path[512];     /* where it mounts, absolute */
    int enabled;        /* started at login (default.target wants it) */
    int mounted;        /* mounted now */
} gaudit_cloud_unit;

typedef struct {
    gaudit_cloud_finding f[GAUDIT_CLOUD_MAX];
    unsigned n;
    int more;
    char gathering[512];        /* the gathering folder, "" for none */
    unsigned gathering_count;   /* how many gathering folders there are (a duplicate: > 1) */
    int rclone_unreadable;      /* rclone's settings are encrypted, or could not be read */
    gaudit_cloud_unit units[GAUDIT_CLOUD_MAX_UNITS];
    unsigned n_units;
} gaudit_cloud_findings;

typedef struct {
    const char *home;
    const char *mounts;   /* default /proc/self/mounts */
    const char *root;     /* prefix for /usr/bin and the like, "" in use; for tests */
} gaudit_cloud_where;

/* 0 when the home folder could be used, -1 otherwise. */
int gaudit_cloud_find(const gaudit_cloud_where *where, gaudit_cloud_findings *out);

/* The "path" values in Dropbox's info.json text, one per account, in order:
 * how many, at most max, each copied into out[i] (absolute, plain). For
 * tests. */
unsigned gaudit_cloud_dropbox_paths(const char *json, char out[][512], unsigned max);
