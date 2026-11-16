/* SPDX-License-Identifier: GPL-3.0-only */
/* Checking and installing a known vendor package (common/vendor.h) on
 * request, as root. The package was downloaded as the user; here it is
 * copied into a folder only root can write, and everything is checked on
 * that copy: the vendor's signature with gpgv and the vendor's key from
 * gAudit's table (its fingerprint, not just any key in the file), every
 * part of the package against the digests the signature lists, the
 * package's name, and that its version is the one asked for and newer
 * than the one installed. Installing takes exactly that copy, still the
 * same bytes, and nothing is left behind either way. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    const char *cache_dir;   /* e.g. "/var/cache/gaudit/vendor" (its parent must exist or be made) */
    const char *keys_dir;    /* GAUDIT_VENDOR_KEYS_DIR */
    uid_t owner;             /* who must own the folders and the key file (0) */
    int check_key_owner;     /* 0 only in developer builds: the key file is the build tree's */
    const char *gpgv, *dpkg_deb, *dpkg_query, *dpkg;  /* absolute paths */
} gaudit_vendor_env;

/* What a check or an install gave: result one of run.h's vendor names. */
typedef struct {
    const char *result;
    char version[40];
    char hash[16];           /* "SHA1", "SHA256", ...; "" unknown */
} gaudit_vendor_outcome;

/* Copies the package at path into env->cache_dir and checks it there. */
void gaudit_vendor_verify(const gaudit_vendor_env *env, const char *id, const char *version,
                          const char *path, gaudit_vendor_outcome *out);

/* Installs the copy checked last for id, if it is still the same bytes;
 * anyway must be 1 when its signature was weak (the user's choice). */
void gaudit_vendor_install(const gaudit_vendor_env *env, const char *id, int anyway,
                           gaudit_vendor_outcome *out);

/* Removes everything in env->cache_dir (never following a link). */
void gaudit_vendor_clean(const gaudit_vendor_env *env);

/* --- Parts, for tests ----------------------------------------------------- */

typedef struct {
    char name[64];
    char md5[33];
    char sha1[41];
    unsigned long long size;
} gaudit_vendor_part;

/* The signed text of a dpkg-sig signature (a cleartext-signed message, the
 * whole of sig, nothing before or after it): Role must be "builder", and
 * its Files are listed into parts. Returns how many, or -1 if it is not
 * exactly such a message. */
int gaudit_vendor_signed_parts(const char *sig, size_t len, gaudit_vendor_part *parts,
                               size_t max);

/* gpgv's status lines: exactly one good, valid signature and nothing else
 * about signatures. fingerprint: the primary key's (40 hex digits); hash:
 * OpenPGP's hash algorithm number. 0 on success, -1 bad, -2 no public key. */
int gaudit_vendor_gpgv_status(const char *status, char fingerprint[41], int *hash);

/* An OpenPGP hash algorithm number's name ("SHA1"); "" for an unknown one. */
const char *gaudit_vendor_hash_name(int hash);
