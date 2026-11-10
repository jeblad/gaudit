/* SPDX-License-Identifier: GPL-3.0-only */
#include "private-files.h"

#include "gaudit/backend.h"

#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SSH_ENTRIES 1000
#define MAX_MATCHES     256  /* per pattern */

/* What group and others must not have. */
#define NO_ACCESS 077  /* private: owner only */
#define NO_WRITE  022  /* may be readable, never writable by others */

typedef struct {
    const char *home;
    uid_t uid;
    gid_t own_gid;  /* the user's private group, or (gid_t)-1 */
    char *first;
    size_t first_len;
    int problems;
} state;

static void report(state *st, const char *rel)
{
    if (st->problems == 0 && st->first != NULL && st->first_len > 0)
        snprintf(st->first, st->first_len, "~/%s", rel);
    st->problems++;
}

/* rel under home must, if it exists, be owned by uid and have none of the
 * forbidden bits. Symlinks are followed: what matters is the target. */
static void check(state *st, const char *rel, mode_t forbidden, int want_dir)
{
    char path[PATH_MAX];
    struct stat sb;
    int n = snprintf(path, sizeof path, "%s/%s", st->home, rel);
    if (n < 0 || (size_t)n >= sizeof path || stat(path, &sb) != 0)
        return;  /* absent (or unreachable): nothing to protect here */
    if (want_dir >= 0 && (S_ISDIR(sb.st_mode) != 0) != (want_dir != 0))
        return;  /* not the kind of thing we look for */
    if (sb.st_uid != st->uid || (sb.st_mode & forbidden) != 0)
        report(st, rel);
}

/* A private key file: id_* without .pub, or a PEM/OpenSSH private key. */
static int looks_private(const char *dir, const char *name)
{
    size_t len = strlen(name);
    if (strncmp(name, "id_", 3) == 0 && !(len > 4 && strcmp(name + len - 4, ".pub") == 0))
        return 1;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof path)
        return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return 0;
    char head[128];
    ssize_t got = read(fd, head, sizeof head - 1);
    close(fd);
    if (got <= 0)
        return 0;
    head[got] = '\0';
    return strncmp(head, "-----BEGIN ", 11) == 0 && strstr(head, "PRIVATE KEY-----") != NULL;
}

/* Every entry in rel (one level) must be private: for folders that hold
 * only secrets, such as GnuPG's private-keys-v1.d. */
static void check_all_inside(state *st, const char *rel)
{
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof dir, "%s/%s", st->home, rel);
    if (n < 0 || (size_t)n >= sizeof dir)
        return;
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    int seen = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && seen++ < MAX_SSH_ENTRIES) {
        if (de->d_name[0] == '.')
            continue;
        char child[PATH_MAX];
        n = snprintf(child, sizeof child, "%s/%s", rel, de->d_name);
        if (n > 0 && (size_t)n < sizeof child)
            check(st, child, NO_ACCESS, -1);
    }
    closedir(d);
}

static void check_ssh_keys(state *st)
{
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof dir, "%s/.ssh", st->home);
    if (n < 0 || (size_t)n >= sizeof dir)
        return;
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    int seen = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && seen++ < MAX_SSH_ENTRIES) {
        if (de->d_name[0] == '.')
            continue;
        char rel[PATH_MAX];
        n = snprintf(rel, sizeof rel, ".ssh/%s", de->d_name);
        if (n < 0 || (size_t)n >= sizeof rel)
            continue;
        if (strcmp(de->d_name, "authorized_keys") == 0 || strcmp(de->d_name, "config") == 0)
            check(st, rel, NO_WRITE, 0);
        else if (looks_private(dir, de->d_name))
            check(st, rel, NO_ACCESS, 0);
    }
    closedir(d);
}

/* Can anyone but the owner read rel? Every folder from home on must let
 * them through and the target itself must be readable (for a folder: its
 * listing). Group bits of the user's own private group count as the
 * owner's. Simplified where groups differ along the way: someone is
 * assumed to have whichever of group and other bits is more generous.
 * Symlinks are followed. -1 if rel does not exist. */
static int reachable_by_others(const state *st, const char *rel)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", st->home, rel);
    if (n < 0 || (size_t)n >= sizeof path)
        return -1;
    struct stat sb;
    if (stat(path, &sb) != 0)
        return -1;
    if (sb.st_uid != st->uid)
        return 1;
    mode_t g_read = sb.st_gid == st->own_gid ? 0 : S_IRGRP;
    if ((sb.st_mode & (g_read | S_IROTH)) == 0)
        return 0;
    /* The folders on the way, from the target's parent up to home. */
    size_t home_len = strlen(st->home);
    for (char *slash = strrchr(path, '/'); slash != NULL && (size_t)(slash - path) >= home_len;
         slash = strrchr(path, '/')) {
        *slash = '\0';
        if (stat(path[0] != '\0' ? path : "/", &sb) != 0)
            return -1;
        mode_t g_x = sb.st_gid == st->own_gid ? 0 : S_IXGRP;
        if ((sb.st_mode & (g_x | S_IXOTH)) == 0)
            return 0;
        if ((size_t)(slash - path) == home_len)
            break;
    }
    return 1;
}

/* Secrets kept by programs, judged by whether anyone else can actually
 * reach them. Globs are relative to home; '*' never crosses a '/'. For
 * profile folders the files that hold the passwords are listed, since a
 * closed profile folder protects readable files inside it. */
static const char *const reach_rules[] = {
    /* Generic credentials. */
    ".netrc", ".pgpass", ".git-credentials", ".my.cnf",
    ".aws/credentials", ".kube/config", ".docker/config.json",
    ".config/gh/hosts.yml", ".config/rclone/rclone.conf",
    /* Password stores and keyrings. */
    ".password-store", ".local/share/kwalletd", ".local/share/keyrings/*",
    ".local/share/gnome-remote-desktop/rdp-tls.key",
    ".pki/nssdb/key4.db",
    /* Firefox and Thunderbird (NSS), also as Snap and Flatpak. */
    ".mozilla/firefox/*/key4.db", ".mozilla/firefox/*/logins.json",
    ".thunderbird/*/key4.db", ".thunderbird/*/logins.json",
    "snap/firefox/common/.mozilla/firefox/*/key4.db",
    "snap/firefox/common/.mozilla/firefox/*/logins.json",
    "snap/thunderbird/common/.thunderbird/*/key4.db",
    "snap/thunderbird/common/.thunderbird/*/logins.json",
    ".var/app/*/.mozilla/firefox/*/key4.db", ".var/app/*/.mozilla/firefox/*/logins.json",
    ".var/app/*/.thunderbird/*/key4.db", ".var/app/*/.thunderbird/*/logins.json",
    /* Chromium-based browsers, also as Snap and Flatpak. */
    ".config/chromium/*/Login Data", ".config/google-chrome/*/Login Data",
    ".config/BraveSoftware/Brave-Browser/*/Login Data", ".config/vivaldi/*/Login Data",
    ".config/microsoft-edge/*/Login Data", ".config/opera/Login Data",
    "snap/chromium/common/chromium/*/Login Data",
    ".var/app/*/config/*/*/Login Data", ".var/app/*/config/BraveSoftware/*/*/Login Data",
    ".var/app/*/.pki/nssdb/key4.db",
};

/* home with glob's special characters escaped, so only the rule's own
 * wildcards are wildcards. */
static int escaped_home(const char *home, char *out, size_t len)
{
    size_t o = 0;
    for (const char *p = home; *p != '\0'; p++) {
        if (strchr("*?[]\\", *p) != NULL) {
            if (o + 1 >= len)
                return -1;
            out[o++] = '\\';
        }
        if (o + 1 >= len)
            return -1;
        out[o++] = *p;
    }
    out[o] = '\0';
    return 0;
}

static void check_reach(state *st, const char *rule)
{
    if (strchr(rule, '*') == NULL) {
        if (reachable_by_others(st, rule) == 1)
            report(st, rule);
        return;
    }
    char pattern[PATH_MAX];
    if (escaped_home(st->home, pattern, sizeof pattern) != 0)
        return;
    size_t plen = strlen(pattern);
    int n = snprintf(pattern + plen, sizeof pattern - plen, "/%s", rule);
    if (n < 0 || (size_t)n >= sizeof pattern - plen)
        return;
    glob_t g;
    if (glob(pattern, GLOB_NOSORT, NULL, &g) != 0)
        return;
    size_t home_len = strlen(st->home);
    for (size_t i = 0; i < g.gl_pathc && i < MAX_MATCHES; i++) {
        const char *rel = g.gl_pathv[i] + home_len + 1;
        if (strlen(g.gl_pathv[i]) > home_len && reachable_by_others(st, rel) == 1)
            report(st, rel);
    }
    globfree(&g);
}

int gaudit_private_files_check(const char *home, uid_t uid, gid_t own_gid,
                               char *first, size_t first_len)
{
    struct stat sb;
    if (home == NULL || home[0] != '/' || stat(home, &sb) != 0 || !S_ISDIR(sb.st_mode)
        || strlen(home) >= PATH_MAX / 2)
        return -1;
    if (first != NULL && first_len > 0)
        first[0] = '\0';

    state st = { home, uid, own_gid, first, first_len, 0 };

    /* The home directory itself: writable by others undoes everything below
     * (and sshd refuses it with StrictModes). */
    if (sb.st_uid != uid || (sb.st_mode & NO_WRITE) != 0)
        report(&st, "");

    check(&st, ".ssh", NO_ACCESS, 1);
    check_ssh_keys(&st);
    /* GnuPG: the folder, the private keys (GnuPG 2) and the old secret
     * keyring (GnuPG 1). Public keyrings may be readable. */
    check(&st, ".gnupg", NO_ACCESS, 1);
    check(&st, ".gnupg/private-keys-v1.d", NO_ACCESS, 1);
    check_all_inside(&st, ".gnupg/private-keys-v1.d");
    check(&st, ".gnupg/secring.gpg", NO_ACCESS, 0);

    for (size_t i = 0; i < sizeof reach_rules / sizeof reach_rules[0]; i++)
        check_reach(&st, reach_rules[i]);

    return st.problems;
}

gaudit_backend_status gaudit_private_files_here(unsigned *out_count, char *first, size_t first_len)
{
    if (out_count == NULL)
        return GAUDIT_BACKEND_ERROR;
    /* The home directory from the password database, not from $HOME. */
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL)
        return GAUDIT_BACKEND_ERROR;
    /* The user's private group, as Ubuntu and most distributions create
     * them: same name as the user, the user's primary group, nobody else
     * listed in it. */
    gid_t own_gid = (gid_t)-1;
    struct group *gr = getgrgid(pw->pw_gid);
    if (gr != NULL && strcmp(gr->gr_name, pw->pw_name) == 0) {
        own_gid = pw->pw_gid;
        for (char **m = gr->gr_mem; *m != NULL; m++)
            if (strcmp(*m, pw->pw_name) != 0)
                own_gid = (gid_t)-1;
    }
    int n = gaudit_private_files_check(pw->pw_dir, getuid(), own_gid, first, first_len);
    if (n < 0)
        return GAUDIT_BACKEND_ERROR;
    *out_count = (unsigned)n;
    return GAUDIT_BACKEND_OK;
}
