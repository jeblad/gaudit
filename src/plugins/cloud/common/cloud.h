/* SPDX-License-Identifier: GPL-3.0-only */
/* The Cloud Services collection's lines, between orchestrator and GUI
 * ("gaudit-orchestrator cloud quick"), parsed strictly on the receiving
 * side. Facts only; what they mean is the rule's.
 *
 *   (cloud-folder (client "...") (service "...") (how N) (path "...") (name "...")
 *                 (encrypted 0|1) (via "...") (gathered 0|1))              one per finding
 *
 * via: the name of the rclone crypt remote over it, "" for none.
 *   (cloud-end (count N) (more 0|1) (gathering "...") (gatherings N) (rclone-unreadable 0|1))  last
 *
 * how: 0 the client's settings name the folder, 1 its default folder is
 * there, 2 installed only, 3 mounted, 4 set up without a folder of its own
 * (cloud-folders.h). path: "~/..." in the home folder, else absolute, ""
 * for none; the same for the gathering folder. */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char client[16];
    char service[16];
    int how;
    char path[256];
    char name[128];
    int encrypted, gathered;
    char via[128];
} gaudit_cloud_line;

typedef struct {
    unsigned count, gatherings;
    int more, rclone_unreadable;
    char gathering[256];
} gaudit_cloud_end;

int gaudit_cloud_format_folder(const gaudit_cloud_line *f, char *buf, size_t len);
int gaudit_cloud_format_end(const gaudit_cloud_end *e, char *buf, size_t len);

/* 1 a folder line, 2 the end, 3 a unit line; -1 for anything else. f, e
 * or u may be NULL. */
typedef struct gaudit_cloud_unit_line gaudit_cloud_unit_line;
int gaudit_cloud_parse_line(const char *line, gaudit_cloud_line *f, gaudit_cloud_end *e);
int gaudit_cloud_parse_unit(const char *line, gaudit_cloud_unit_line *u);

/* --- The services the rclone page can set up -------------------------------- */

typedef struct {
    const char *id;          /* the collection's service id */
    const char *name;        /* shown, never translated; also the folder under ~/Cloud */
    const char *type;        /* rclone's storage type */
    const char *token_page;  /* where the login token is made */
    const char *remote;      /* the name suggested for the remote */
} gaudit_cloud_setup_service;

extern const gaudit_cloud_setup_service gaudit_cloud_setup_services[];
extern const unsigned gaudit_cloud_setup_services_count;
const gaudit_cloud_setup_service *gaudit_cloud_setup_find(const char *id);

/* An rclone remote's name that may go into a unit file: [A-Za-z0-9_.-],
 * not starting with '-' or '.', at most 64. */
int gaudit_cloud_plain_remote(const char *name);

/* --- Mounting at each login: a systemd user unit --------------------------------
 *
 * The text shown on the page and the file written come from this one
 * function, so they cannot drift apart. ~/.config/systemd/user/
 * rclone-<id>.service, mounting <remote>: at ~/Cloud/<name>. */

/* The unit's file name ("rclone-jottacloud.service"). */
void gaudit_cloud_unit_name(const gaudit_cloud_setup_service *s, char *out, size_t len);

/* The unit's text; 0, or -1 when the remote is not plain or it does not fit. */
int gaudit_cloud_unit_text(const gaudit_cloud_setup_service *s, const char *remote, char *out,
                           size_t len);

/* What the collection says of a unit of gAudit's kind (rclone-*.service):
 *
 *   (cloud-unit (file "...") (path "...") (enabled 0|1) (mounted 0|1))
 *
 * and what writing one did:
 *
 *   (cloud-unit-written (result "written|unchanged|foreign|refused|error")) */
struct gaudit_cloud_unit_line {
    char file[64];
    char path[256];
    int enabled, mounted;
};
int gaudit_cloud_format_unit(const gaudit_cloud_unit_line *u, char *buf, size_t len);

#ifdef __cplusplus
}
#endif
