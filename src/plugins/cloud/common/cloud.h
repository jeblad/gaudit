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
    const char *name;        /* shown, never translated; also its folder's name */
    const char *type;        /* rclone's storage type */
    const char *token_page;  /* where the login token is made; NULL: rclone logs in
                                through the browser, the answer coming back to it on
                                this computer (127.0.0.1) */
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
 * rclone-<id>-private.service or rclone-<id>-shared.service, mounting a
 * remote under the gathering folder (John, 2026-11-19). The user chooses
 * the private disk, the crypt remote; the shareable one, the plain remote
 * without the encrypted folder; or both. A disk is always named with its
 * kind, in the words of the language ("Dropbox (privat)", "Dropbox (delt
 * mappe)"), also when it is the only one, so the name says what it is
 * wherever a file is saved, and adding the other never renames it (John,
 * 2026-11-19). Units made before, named rclone-<id>.service, are still
 * recognised. */

typedef enum {
    GAUDIT_CLOUD_DISK_PRIVATE = 0,
    GAUDIT_CLOUD_DISK_SHARED,
} gaudit_cloud_disk;

/* "private", "shared" and back; -1 for anything else. */
const char *gaudit_cloud_disk_word(gaudit_cloud_disk disk);
int gaudit_cloud_disk_parse(const char *word);

/* The unit's file name ("rclone-dropbox-private.service"). */
void gaudit_cloud_unit_name(const gaudit_cloud_setup_service *s, gaudit_cloud_disk disk,
                            char *out, size_t len);

/* The mount point's name under the gathering folder, with the words of the
 * language given ("Dropbox (privat)"); the words are passed so this file
 * needs nothing of the backend's. */
void gaudit_cloud_folder_name(const gaudit_cloud_setup_service *s, gaudit_cloud_disk disk,
                              const char *private_word, const char *shared_word, char *out,
                              size_t len);

/* A name that may go into a unit between double quotes and a path: not
 * empty, not "." or "..", no '/', '"', '\\', '%', '\'' or control
 * characters, at most 64 bytes. */
int gaudit_cloud_plain_folder(const char *name);

/* The unit's text: remote (the crypt remote for the private disk), mounted
 * at ~/<gathering>/<folder>; 0, or -1 when a name is not plain or it does
 * not fit. */
int gaudit_cloud_unit_text(const gaudit_cloud_setup_service *s, gaudit_cloud_disk disk,
                           const char *remote, const char *gathering, const char *folder,
                           char *out, size_t len);

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

/* --- Files outside the encrypted folder, looked for on a click ------------------
 *
 * Asked of the service itself, so only when the user presses the button on
 * its page, never in the collection (John, 2026-11-19): "gaudit-orchestrator
 * cloud plain <remote>" lists the remote's top level without the encrypted
 * folder, with rclone, and counts; no name leaves it. The GUI puts the line
 * into the cached collection, so the report and Home follow.
 *
 *   (cloud-plain (remote "...") (status 0|1|2) (count N) (more 0|1))
 *
 * status 0 counted; 1 could not be found out (no connection, the service
 * did not answer, rclone failed); 2 cannot be told apart, the encryption
 * covering the whole remote. count: files and folders at the top level,
 * at most GAUDIT_CLOUD_PLAIN_MAX; more: there were more than that. */
#define GAUDIT_CLOUD_PLAIN_MAX 1000
typedef struct {
    char remote[128];
    int status;
    unsigned count;
    int more;
} gaudit_cloud_plain_line;
int gaudit_cloud_format_plain(const gaudit_cloud_plain_line *p, char *buf, size_t len);
/* 0, or -1 for anything else. */
int gaudit_cloud_parse_plain(const char *line, gaudit_cloud_plain_line *p);

/* --- Secrets in cloud folders (John, 2026-11-19) ----------------------------------
 *
 * Files that look like secrets (keys, password databases, stored logins)
 * where a cloud service gets them. Folders kept in step on this computer
 * are searched as the private files are, in the full collection only,
 * never on another filesystem. A shareable rclone disk is looked at on a
 * click only, by names alone ("gaudit-orchestrator cloud names <remote>"),
 * since its content is fetched over the network. Never content.
 *
 *   (cloud-secret (service "...") (remote "...") (path "...") (reason "...") (by-name 0|1))
 *
 * remote "" for a local folder, path then "~/..." or absolute; else the
 * rclone remote's name, path relative to it. by-name: known by its name
 * alone, a guess (cloud names).
 *
 *   (cloud-secret-scan (folders N) (found N) (more 0|1) (truncated 0|1))
 *
 * the local search: folders searched, secrets found (at most
 * GAUDIT_CLOUD_SECRETS_MAX sent), more: not all sent, truncated: a search
 * stopped at its limit.
 *
 *   (cloud-names (remote "...") (status 0|1) (looked N) (found N) (more 0|1) (truncated 0|1))
 *
 * the names of one remote: status 1 could not be found out; looked: names
 * looked at; truncated: stopped at GAUDIT_CLOUD_NAMES_MAX names or the time
 * limit. */
#define GAUDIT_CLOUD_SECRETS_MAX 100
#define GAUDIT_CLOUD_NAMES_MAX 200000

typedef struct {
    char service[16];
    char remote[128];
    char path[256];      /* the line parser's limit; a longer one is left out */
    char reason[32];
    int by_name;
} gaudit_cloud_secret_line;

typedef struct {
    unsigned folders, found;
    int more, truncated;
} gaudit_cloud_secret_scan_line;

typedef struct {
    char remote[128];
    int status;
    unsigned looked, found;
    int more, truncated;
} gaudit_cloud_names_line;

int gaudit_cloud_format_secret(const gaudit_cloud_secret_line *l, char *buf, size_t len);
int gaudit_cloud_format_secret_scan(const gaudit_cloud_secret_scan_line *l, char *buf, size_t len);
int gaudit_cloud_format_names(const gaudit_cloud_names_line *l, char *buf, size_t len);
/* 0, or -1 for anything else; l may be NULL. */
int gaudit_cloud_parse_secret(const char *line, gaudit_cloud_secret_line *l);
int gaudit_cloud_parse_secret_scan(const char *line, gaudit_cloud_secret_scan_line *l);
int gaudit_cloud_parse_names(const char *line, gaudit_cloud_names_line *l);

#ifdef __cplusplus
}
#endif
