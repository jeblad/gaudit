/* SPDX-License-Identifier: GPL-3.0-only */
/* Known vendor packages without a software source: the vendor offers only
 * a package to download, so the system never updates it. gAudit's own
 * fixed table, never from a plugin or the package itself; a package is
 * known only by its name *and* its maker as the package database has it,
 * so another package with the same name is not taken for it. Plain C, no
 * dependencies: compiled into the orchestrator and the GUI. */
#pragma once

#include <stddef.h>

/* A signing key the vendor uses, with when it applies from and where its
 * fingerprint was taken: putting it here is gAudit vouching that the key
 * is the vendor's, nothing about the software. Only keys for versions
 * gAudit may install: older keys are left out, since nothing older than
 * what is installed is ever installed. */
typedef struct {
    const char *fingerprint;  /* 40 hex digits, upper case, no spaces */
    const char *from_version; /* the first version signed with it, as the vendor says */
    const char *taken;        /* where and when the fingerprint was taken */
} gaudit_vendor_key;

typedef enum {
    GAUDIT_FLATPAK_NOT_CHECKED = 0,  /* the page says what the marks mean */
    GAUDIT_FLATPAK_VERIFIED,         /* "Verified": the vendor makes it */
    GAUDIT_FLATPAK_UNVERIFIED,       /* "Unverified": someone else does */
} gaudit_vendor_flatpak_mark;

typedef struct {
    const char *id;           /* stable, e.g. "zoom" */
    const char *package;      /* the package name, e.g. "zoom" */
    const char *maker;        /* Debian's Maintainer up to " <", e.g. "Zoom Communications, Inc." */
    const char *title;        /* the program's name, e.g. "Zoom" (never translated) */
    const char *vendor;       /* who offers it, e.g. "Zoom" */
    const char *download;     /* the vendor's download page, https */
    const char *flatpak;      /* a Flatpak app id on Flathub, or NULL */
    const char *latest;       /* https address that redirects to the newest package, or NULL */
    const char *prefix;       /* the redirect must be exactly prefix <version> suffix */
    const char *suffix;
    const char *key_file;     /* in GAUDIT_VENDOR_KEYS_DIR, e.g. "zoom.gpg"; NULL when the
                                 vendor signs nothing: then gAudit never installs it */
    const gaudit_vendor_key *keys;
    size_t n_keys;
    /* Who makes the Flatpak, as Flathub marks it, checked by hand like the
     * keys (flatpak_checked: where and when): the page then says so. */
    gaudit_vendor_flatpak_mark flatpak_mark;
    const char *flatpak_checked;
    /* A snap published by the vendor itself, or NULL; checked by hand
     * (snap_checked: where and when). Only the vendor's own is named. */
    const char *snap;
    const char *snap_checked;
} gaudit_vendor_package;

/* The entry for an installed package with this name and Maintainer field
 * (as dpkg has it, "Name <address>"), or NULL. */
const gaudit_vendor_package *gaudit_vendor_match(const char *package, const char *maintainer);

/* The version in a redirect from p->latest ("https://cdn.zoom.us/prod/
 * 7.2.5.6661/zoom_amd64.deb"): exactly p->prefix, a version of digits and
 * single dots, p->suffix. It comes from the network, so it only decides
 * what a page shows. 1 with version set, 0 otherwise. */
int gaudit_vendor_version_from(const gaudit_vendor_package *p, const char *location,
                               char *version, size_t len);

/* Whether a package with this name is in the table at all, whoever made
 * it: the cheap test before its maker is read. 1 yes, 0 no. */
int gaudit_vendor_name_known(const char *package);

/* The entry with this id, or NULL. */
const gaudit_vendor_package *gaudit_vendor_find(const char *id);

/* A version as gAudit takes it from a vendor: digits and single dots, at
 * most 32 characters. 1 yes. */
int gaudit_vendor_plain_version(const char *version);

/* The arguments of "vendor-verify <id> <version> <path>": an id in the
 * table, a plain version, and an absolute path ending in
 * "/.cache/gaudit/vendor/<id>.deb" without "." or ".." parts or control
 * characters. 1 yes. */
int gaudit_vendor_verify_args_ok(const char *id, const char *version, const char *path);

/* --- Local copies of a vendor's source -------------------------------------
 *
 * A vendor's "local" installer puts a copy of its software source on the
 * disk (a folder in /var with a Packages index) and sets it up as a file:
 * source. The copy never changes, so what came from it never gets updates.
 * Recognised by the folder's name; what it made for and which version are
 * read from the name, the packages from its own index. */
typedef struct {
    const char *id;             /* e.g. "cuda" */
    const char *title;          /* the product, e.g. "CUDA" (never translated) */
    const char *vendor;         /* e.g. "NVIDIA" */
    const char *dir_prefix;     /* the folder in /var: dir_prefix <release>-<version> dir_suffix */
    const char *dir_suffix;
    const char *download;       /* the vendor's download page, https */
    const char *versioned;      /* prefix of the package that keeps one version, e.g.
                                   "cuda-toolkit-" (then "13-3"); NULL for none */
    const char *const *network; /* releases the vendor has a network source for (x86_64),
                                   e.g. "ubuntu2604"; NULL-terminated */
    const char *checked;        /* where and when that list was checked */
} gaudit_vendor_local;

const gaudit_vendor_local *gaudit_vendor_local_find(const char *id);

/* The entry whose folder this is (a name in /var, e.g.
 * "cuda-repo-ubuntu2604-13-3-local"), with the release it was made for
 * ("ubuntu2604") and the version ("13.3"); NULL for none. */
const gaudit_vendor_local *gaudit_vendor_local_match(const char *dir_name, char *release,
                                                     size_t release_len, char *version,
                                                     size_t version_len);

/* The n-th entry, NULL past the end. */
const gaudit_vendor_local *gaudit_vendor_local_at(size_t n);

/* 1 when the vendor has a network source for release. */
int gaudit_vendor_local_has_network(const gaudit_vendor_local *v, const char *release);

/* A release as gAudit names it, from os-release's ID and VERSION_ID:
 * "ubuntu" "26.10" -> "ubuntu2610", "debian" "13" -> "debian13". 1 on success. */
int gaudit_vendor_release_id(const char *id, const char *version_id, char *out, size_t len);

/* And as people read it: "ubuntu2604" -> "Ubuntu 26.04", "debian13" -> "Debian 13";
 * the id itself for anything else. */
void gaudit_vendor_release_name(const char *release, char *out, size_t len);

/* --- Packages another program keeps up to date ------------------------------
 *
 * A package a program installs on the host itself, and replaces when it is
 * updated (ClamUI's privileged helper): it has a source, only not apt. Known
 * by name and maker, as the vendor packages; the program that manages it is
 * there when its Flatpak app or its package is installed. */
typedef struct {
    const char *id;          /* e.g. "clamui-helper" */
    const char *package;     /* e.g. "clamui-privileged-helper" */
    const char *maker;       /* Debian's Maintainer up to " <" */
    const char *manager;     /* the program, e.g. "ClamUI" (never translated) */
    const char *flatpak;     /* its Flatpak app id, or NULL */
    const char *deb;         /* its own package, or NULL */
} gaudit_vendor_companion;

const gaudit_vendor_companion *gaudit_vendor_companion_match(const char *package,
                                                             const char *maintainer);
const gaudit_vendor_companion *gaudit_vendor_companion_find(const char *id);
/* Whether a companion with this package name is in the table at all. */
int gaudit_vendor_companion_name_known(const char *package);
