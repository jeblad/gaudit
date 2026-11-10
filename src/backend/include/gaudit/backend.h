/* SPDX-License-Identifier: GPL-3.0-only */
/* Distro backend interfaces. Checks talk to these, never directly to
 * apt/dpkg/ufw/etc., so another distro only needs a new backend.
 * One struct of function pointers per area (pkg, firewall, scheduler, ...).
 */
#pragma once

#include <stddef.h>
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

/* Snap status from snapd's local API. */
typedef struct {
    int running;            /* snapd answered */
    unsigned snaps;
    unsigned devmode;       /* developer mode: sandbox violations only logged */
    unsigned classic;       /* classic confinement: no sandbox, by design */
    unsigned held;          /* held back from refreshes by the user */
    long long last_refresh; /* seconds since epoch, 0 if unknown */
    long long refresh_hold; /* refreshes held system-wide until then, 0 if not */
} gaudit_snap_state;

/* Package systems gAudit can recognise on disk (not necessarily check). */
typedef enum {
    GAUDIT_PKGSYS_DPKG = 0,
    GAUDIT_PKGSYS_RPM,
    GAUDIT_PKGSYS_PACMAN,
    GAUDIT_PKGSYS_PKGTOOLS,  /* Slackware */
    GAUDIT_PKGSYS_APK,       /* Alpine */
    GAUDIT_PKGSYS_PORTAGE,   /* Gentoo */
    GAUDIT_PKGSYS_XBPS,      /* Void */
    GAUDIT_PKGSYS_NIX,
    GAUDIT_PKGSYS_GUIX,
    GAUDIT_PKGSYS_COUNT
} gaudit_package_system;

/* An abstract capability a task depends on (e.g. "clamav"), mapped by the
 * backend to concrete programs and the packages that provide them. */
typedef struct gaudit_capability {
    const char *id;
    const char *const *paths;     /* absolute paths, NULL-terminated */
    const char *const *packages;  /* NULL-terminated */
} gaudit_capability;

typedef struct gaudit_pkg_backend {
    const char *name;

    /* Shown to the user, e.g. "dpkg/apt". NULL for the generic backend. */
    const char *package_system;

    /* Feature detection: 1 if this backend's package system is present.
     * The backend is chosen by this, never by the distribution's name. */
    int (*detect)(void);

    /* The package system this backend checks (gaudit_package_system), or -1. */
    int own_package_system;

    /* Bitmask (1 << gaudit_package_system) of package systems with
     * installed packages on this machine. */
    unsigned (*package_systems_present)(void);

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

    /* Snap, if in use; statuses as for flatpak_state. Capability
     * "libjson-glib" names the package when the library is missing. */
    gaudit_backend_status (*snap_state)(gaudit_snap_state *out);
} gaudit_pkg_backend;

/* Debian family (Debian, Ubuntu and derivatives): dpkg/apt. */
const gaudit_pkg_backend *gaudit_pkg_backend_debian(void);

/* Any other distribution: common paths and Flatpak only. */
const gaudit_pkg_backend *gaudit_pkg_backend_generic(void);

/* The backend for the running system, chosen by feature detection: the
 * first backend whose package system is present, else the generic one. */
const gaudit_pkg_backend *gaudit_pkg_backend_default(void);

/* The backend /etc/os-release leads us to expect (e.g. Debian for Ubuntu),
 * or NULL when the distribution gives no expectation. Only used to warn
 * when the expected package system is missing. */
const gaudit_pkg_backend *gaudit_pkg_backend_expected(void);

/* For display only; each is "" when it cannot be determined.
 *   host    host name
 *   name    short distribution name ("Ubuntu")
 *   full    name, version and code name ("Ubuntu 26.10 Stonking Stoat") */
void gaudit_system_describe(char *host, size_t host_len, char *name, size_t name_len,
                            char *full, size_t full_len);

/* Display name, e.g. "rpm" or "pkgtools (Slackware)". Not translated. */
const char *gaudit_package_system_label(gaudit_package_system s);

/* Package systems with installed packages under root ("" or NULL: this
 * machine), detected by their databases on disk. Bitmask as above. */
unsigned gaudit_package_systems_present(const char *root);
unsigned gaudit_package_systems_present_here(void);

/* 1 if every path of the capability exists and is executable, else 0.
 * Presentation only: the helper re-checks anything that matters. */
int gaudit_capability_present(const gaudit_capability *cap);

#ifdef __cplusplus
}
#endif
