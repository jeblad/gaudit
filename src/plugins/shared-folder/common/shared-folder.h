/* SPDX-License-Identifier: GPL-3.0-only */
/* The Shared Folder collection's lines, between orchestrator and GUI
 * ("gaudit-orchestrator shared quick"), parsed strictly on the receiving
 * side:
 *
 *   (shared-config (state S) (standard "...") (exists 0|1) (locale "...") (default "...")
 *                  (names N))
 *   (shared-folder (name "...") (lang "...") (machine 0|1) (current 0|1) (standard 0|1)
 *                  (link 0|1) (target "...") (case 0|1) (entries N))      one per folder
 *   (shared-service (kind "...") (name "...") (path "..."))              one per service
 *   (shared-end (folders N) (services N) (more 0|1) (usershares 0|1))    last
 *
 * state: 0 none set up, 1 set, 2 switched off, 3 could not be read. The
 * standard folder is "~/name" when it is in the home folder, else
 * absolute. A folder's name is straight in the home folder. entries:
 * counted up to 1000, -1 could not be read, -2 on another filesystem (a
 * mount), not looked in. kind: "samba", "samba-user",
 * "gnome". usershares: 1 when Samba's usershares could not be read.
 *
 * The tidying, on request ("gaudit-orchestrator shared check|merge <from>
 * <to>", "shared remove <name>"):
 *
 *   (shared-clash (name "..."))                                           at most 16
 *   (shared-moves (result R) (moved N) (clashes N) (other-disk N) (failed N))
 *   (shared-removed (result R))
 *
 * result: 0 done (or, for check, all can go), 1 something stands in the
 * way (nothing moved; for remove, not empty), 2 refused (a service shares
 * one of the folders, or not plain names, links, not the user's). */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int state;
    char standard[256];
    int exists;
    char locale[64];
    char default_name[128];
    unsigned names;
} gaudit_shared_config;

typedef struct {
    char name[256];
    char lang[32];
    int machine, current, standard, link;
    char target[256];
    int case_differs;
    long entries;
} gaudit_shared_folder;

typedef struct {
    char kind[16];
    char name[128];
    char path[256];
} gaudit_shared_service;

typedef struct {
    unsigned folders, services;
    int more, usershares;
} gaudit_shared_end;

typedef struct {
    int result;
    unsigned moved, clashes, other_disk, failed;
} gaudit_shared_moves;

typedef enum {
    GAUDIT_SHARED_LINE_CONFIG = 1,
    GAUDIT_SHARED_LINE_FOLDER,
    GAUDIT_SHARED_LINE_SERVICE,
    GAUDIT_SHARED_LINE_END,
} gaudit_shared_line;

/* One line written (newline at the end); 0, or -1 when it does not fit. */
int gaudit_shared_format_config(const gaudit_shared_config *c, char *buf, size_t len);
int gaudit_shared_format_folder(const gaudit_shared_folder *f, char *buf, size_t len);
int gaudit_shared_format_service(const gaudit_shared_service *s, char *buf, size_t len);
int gaudit_shared_format_end(const gaudit_shared_end *e, char *buf, size_t len);

/* One collection line: its kind (gaudit_shared_line), the matching struct
 * filled in (any may be NULL when not wanted); -1 for anything else. */
int gaudit_shared_parse_line(const char *line, gaudit_shared_config *c, gaudit_shared_folder *f,
                             gaudit_shared_service *s, gaudit_shared_end *e);

/* --- Secrets in folders for sharing (John, 2026-11-19) -----------------------
 *
 * Files that look like secrets in the folder for sharing and the folders
 * that look like it, and, in the full collection, in every folder a service
 * shares, searched as the private files are; never a folder on another
 * filesystem than the home folder, never through a link. Never content.
 *
 *   (shared-secret (path "...") (reason "...") (by "samba|samba-user|gnome|"))
 *   (shared-secret-scan (folders N) (skipped N) (found N) (more 0|1) (truncated 0|1))
 *
 * path "~/..." in the home folder, else absolute; by: the kind of the
 * first service that shares the folder it is in, "" for none. skipped:
 * folders not looked in (on another filesystem, or a link). At most
 * GAUDIT_SHARED_SECRETS_MAX secrets are sent, found counts them all. */
#define GAUDIT_SHARED_SECRETS_MAX 100

typedef struct {
    char path[256];
    char reason[32];
    char by[16];
} gaudit_shared_secret;

typedef struct {
    unsigned folders, skipped, found;
    int more, truncated;
} gaudit_shared_secret_scan;

int gaudit_shared_format_secret(const gaudit_shared_secret *s, char *buf, size_t len);
int gaudit_shared_format_secret_scan(const gaudit_shared_secret_scan *s, char *buf, size_t len);
/* 0, or -1 for anything else; s may be NULL. */
int gaudit_shared_parse_secret(const char *line, gaudit_shared_secret *s);
int gaudit_shared_parse_secret_scan(const char *line, gaudit_shared_secret_scan *s);

/* The tidying's lines: 1 a clash (name filled in), 2 the moves, 3 removed
 * (result in moves->result); -1 for anything else. */
int gaudit_shared_parse_tidy(const char *line, char *clash, size_t clash_len,
                             gaudit_shared_moves *moves);

#ifdef __cplusplus
}
#endif
