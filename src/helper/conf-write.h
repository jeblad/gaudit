/* SPDX-License-Identifier: GPL-3.0-only */
/* Writing configuration as root: gAudit's own files only, stopped when in
 * doubt.
 *
 * The user starts a change; the change itself is automatic, but only
 * when every precondition holds at the moment of writing. gAudit keeps a
 * register of the files it wrote (path, SHA-256, template and values,
 * modelled on ucf). A target that does not exist may be created; one in
 * the register whose content is still what gAudit wrote may be replaced;
 * anything else is left alone and the caller describes the problem
 * instead. Nothing here edits a file someone else wrote.
 *
 * Every folder from the root down to the file must belong to the expected
 * owner (root) and not be writable by group or others, and is opened
 * without following symbolic links. A new file is written beside the
 * target under a name apt and systemd ignore (a leading dot), synced, and
 * renamed over it; the target is checked again right before the rename.
 * Only the owner of those folders could change anything in between. The
 * register is updated after the file: a crash between the two leaves a
 * file the register does not know, which then counts as foreign, so the
 * failure is to stop, never to overwrite. One lock serialises it all.
 *
 * Paths are relative to the root and may only hold [A-Za-z0-9._-] and
 * '/', no empty or dot-led components; template ids and values only
 * [a-z0-9._-]. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

#define GAUDIT_CONF_MAX_FILE   (64 * 1024)
#define GAUDIT_CONF_MAX_ENTRIES 256

typedef struct {
    const char *root;      /* "/" on a real system; a test tree in tests */
    const char *register_dir;  /* relative to root, e.g. "var/lib/gaudit" */
    uid_t owner;           /* who must own every folder on the way: 0 */
} gaudit_conf_env;

typedef enum {
    GAUDIT_EXPECT_ABSENT,  /* the file must not exist */
    GAUDIT_EXPECT_DIGEST,  /* it must exist with exactly this content */
    GAUDIT_EXPECT_PRESENT, /* it must exist, as a regular file of the owner */
} gaudit_conf_expect_kind;

/* A precondition on another file than the target. */
typedef struct {
    const char *path;
    gaudit_conf_expect_kind kind;
    const char *sha256;    /* 64 hex digits, for GAUDIT_EXPECT_DIGEST */
} gaudit_conf_expect;

typedef struct {
    const char *path;        /* the target, e.g. "etc/apt/apt.conf.d/52gaudit-automatic-updates" */
    const char *template_id; /* e.g. "core.updates.automatic" */
    const char *values;      /* e.g. "on" */
    const char *content;
    size_t len;
    mode_t mode;             /* e.g. 0644 */
    const gaudit_conf_expect *expect;
    size_t n_expect;
} gaudit_conf_plan;

typedef enum {
    GAUDIT_CONF_WRITTEN,      /* created or replaced */
    GAUDIT_CONF_UNCHANGED,    /* already exactly this */
    GAUDIT_CONF_REMOVED,
    GAUDIT_CONF_NOT_THERE,    /* nothing of gAudit's to remove */
    GAUDIT_CONF_FOREIGN,      /* the target exists and is not gAudit's */
    GAUDIT_CONF_EDITED,       /* gAudit's, but changed since it was written */
    GAUDIT_CONF_PRECONDITION, /* another file is not as expected */
    GAUDIT_CONF_UNSAFE,       /* a folder on the way is missing, a link, or writable by others */
    GAUDIT_CONF_ERROR,        /* bad arguments, a damaged register, or I/O */
} gaudit_conf_result;

/* Stable names for the protocol ("written", "foreign", ...). */
const char *gaudit_conf_result_name(gaudit_conf_result r);

gaudit_conf_result gaudit_conf_write(const gaudit_conf_env *env, const gaudit_conf_plan *plan);

/* Removes path if the register lists it and it is still what gAudit wrote. */
gaudit_conf_result gaudit_conf_remove(const gaudit_conf_env *env, const char *path);

/* Whether the register lists path with its current content: 1 yes, 0 no,
 * -1 cannot tell. template_id and values, if not NULL, get the entry's
 * (at least 64 bytes each). */
int gaudit_conf_owned(const gaudit_conf_env *env, const char *path, char *template_id,
                      char *values);
