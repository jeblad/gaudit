/* SPDX-License-Identifier: GPL-3.0-only */
/* The signed manifest: every file of gAudit's own with its SHA-256 and
 * size, signed with gAudit's key (Ed25519, in minisign's format, so the
 * release can be signed with the minisign tool and an offline key). The
 * helper is the anchor: it holds the public keys and checks the rest.
 *
 * The manifest, line by line, nothing else:
 *
 *   gaudit-manifest 1
 *   version <N>                 increasing; lower than the last seen is refused
 *   signed <seconds since 1970> when it was signed (covered by the signature)
 *   expires <seconds since 1970>
 *   file <sha256 hex> <size> <absolute path>     one per file
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* A public key, as minisign's public key file holds it. */
typedef struct {
    unsigned char id[8];
    unsigned char pk[32];
} gaudit_manifest_key;

typedef struct {
    char path[256];
    char sha256[65];
    unsigned long long size;
} gaudit_manifest_file;

typedef struct {
    unsigned long long version;
    int64_t signed_at, expires;
    gaudit_manifest_file *files;
    size_t n_files;
} gaudit_manifest;

typedef enum {
    GAUDIT_MANIFEST_OK = 0,
    GAUDIT_MANIFEST_BAD_SIGNATURE,  /* not signed by any key given, or not a signature */
    GAUDIT_MANIFEST_BAD_FORMAT,     /* signed, but not a manifest this helper can read */
    GAUDIT_MANIFEST_EXPIRED,
    GAUDIT_MANIFEST_TOO_OLD,        /* a version lower than the lowest allowed */
    GAUDIT_MANIFEST_FROM_FUTURE,    /* signed later than now: a clock or a forgery */
} gaudit_manifest_status;

/* A minisign public key file's text into *key. 0 on success. */
int gaudit_manifest_key_parse(const char *text, gaudit_manifest_key *key);

/* Whether sig (a minisign signature file's text) is a good signature of
 * data by one of keys, both the signature and its trusted comment. 1 yes. */
int gaudit_manifest_signature_ok(const unsigned char *data, size_t len, const char *sig,
                                 const gaudit_manifest_key *keys, size_t n_keys);

/* Strict parser of the manifest's text into *m (files allocated; free with
 * gaudit_manifest_free). 0 on success. */
int gaudit_manifest_parse(const char *text, size_t len, gaudit_manifest *m);
void gaudit_manifest_free(gaudit_manifest *m);

/* The whole check: signature, format, then time and version. On OK, *m is
 * filled (free it). min_version: the lowest allowed (the built-in minimum,
 * or the last version seen, whichever is higher). */
gaudit_manifest_status gaudit_manifest_load(const unsigned char *data, size_t len, const char *sig,
                                            const gaudit_manifest_key *keys, size_t n_keys,
                                            int64_t now, unsigned long long min_version,
                                            gaudit_manifest *m);

typedef enum {
    GAUDIT_MANIFEST_FILE_OK = 0,
    GAUDIT_MANIFEST_FILE_CHANGED,   /* another size or digest */
    GAUDIT_MANIFEST_FILE_MISSING,   /* gone, or not a plain file (a link, a folder) */
} gaudit_manifest_file_status;

/* One file against its line: opened without following a link, read once. */
gaudit_manifest_file_status gaudit_manifest_check_file(const gaudit_manifest_file *f);

const char *gaudit_manifest_status_name(gaudit_manifest_status s);
