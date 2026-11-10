/* SPDX-License-Identifier: GPL-3.0-only */
/* Distro backend interfaces. Checks talk to these, never directly to
 * apt/dpkg/ufw/etc., so another distro only needs a new backend.
 * One struct of function pointers per area (pkg, firewall, scheduler, ...).
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GAUDIT_BACKEND_OK = 0,
    GAUDIT_BACKEND_NOT_IMPLEMENTED,
    GAUDIT_BACKEND_UNAVAILABLE,  /* the facility does not exist on this system */
    GAUDIT_BACKEND_ERROR,        /* exists, but the state could not be determined */
    GAUDIT_BACKEND_MISSING_DEPENDENCY,  /* software needed for the check is not installed */
} gaudit_backend_status;

/* Flatpak status from local data only. */
typedef struct {
    unsigned apps;        /* installed apps */
    unsigned eol_apps;    /* apps that are, or use a runtime that is, end-of-life */
    unsigned eol_unused;  /* unused end-of-life refs that can be removed */
    unsigned eol_pinned;  /* end-of-life runtimes no app uses, kept (pinned) */
} gaudit_flatpak_state;

/* An abstract capability a task depends on (e.g. "clamav"), mapped by the
 * backend to concrete programs and the packages that provide them. */
typedef struct gaudit_capability {
    const char *id;
    const char *const *paths;     /* absolute paths, NULL-terminated */
    const char *const *packages;  /* NULL-terminated */
} gaudit_capability;

typedef struct gaudit_pkg_backend {
    const char *name;

    /* Shown to the user for manual installation, followed by package names. */
    const char *manual_install_command;

    /* Fallback when PackageKit is unavailable: run with execve via pkexec,
     * package names appended after the final "--". NULL-terminated. */
    const char *const *fallback_install_argv;

    /* NULL when the capability is unknown on this distro. */
    const gaudit_capability *(*capability)(const char *id);

    /* Time of the last package index update, seconds since epoch. */
    gaudit_backend_status (*last_index_update)(int64_t *out_epoch);

    /* Whether updates are installed automatically (1) or not (0). */
    gaudit_backend_status (*automatic_updates)(int *out_enabled);

    /* Installed packages no software source offers any more, and packages
     * an upgrade would update. */
    gaudit_backend_status (*package_state)(unsigned *out_obsolete, unsigned *out_upgradable);

    /* Flatpak, if in use. UNAVAILABLE: Flatpak is not installed.
     * NOT_IMPLEMENTED: built without the collector. MISSING_DEPENDENCY:
     * the library is missing; capability "libflatpak" names the package. */
    gaudit_backend_status (*flatpak_state)(gaudit_flatpak_state *out);
} gaudit_pkg_backend;

const gaudit_pkg_backend *gaudit_pkg_backend_ubuntu(void);

/* The backend for the running system. */
const gaudit_pkg_backend *gaudit_pkg_backend_default(void);

/* 1 if every path of the capability exists and is executable, else 0.
 * Presentation only: the helper re-checks anything that matters. */
int gaudit_capability_present(const gaudit_capability *cap);

#ifdef __cplusplus
}
#endif
