/* SPDX-License-Identifier: GPL-3.0-only */
#include "secret-scan.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DEPTH    12
#define MAX_ENTRIES  500000
#define MAX_SNIFF    (64 * 1024)  /* key files are small; larger files are only judged by name */

/* Folders that are large, rebuilt by tools, and practically never hold
 * secrets of their own. Trash is deliberately not here: a discarded key is
 * still a key. */
static const char *const skip_dirs[] = {
    ".cache", "node_modules", ".git", ".hg", ".svn", ".npm", ".cargo/registry",
    ".rustup", ".m2/repository", ".gradle/caches", "go/pkg", ".local/share/flatpak",
    ".var/app/*/cache", "snap/*/*/.cache", ".local/share/Steam/steamapps",
    ".steam", ".wine/drive_c/windows", ".local/lib/python*", ".pyenv", ".nvm",
    ".vscode/extensions", ".mozilla/firefox/*/cache2", ".config/*/Cache",
    ".config/*/Code Cache", ".config/*/GPUCache", "site-packages", "__pycache__",
    ".rbenv", ".poetry", ".local/share/pypoetry", ".local/share/containers/storage",
    ".flatpak-builder",
};

/* Never read by content: code, documentation, media and build output. A
 * key pasted into source code is out of scope here; keys kept as files
 * (.pem, .key, no extension) are still read. */
static const char *const no_sniff[] = {
    "*.c", "*.h", "*.cc", "*.cpp", "*.hpp", "*.o", "*.a", "*.so", "*.so.*", "*.py", "*.pyc",
    "*.rb", "*.ri", "*.js", "*.mjs", "*.ts", "*.go", "*.rs", "*.java", "*.class", "*.jar",
    "*.md", "*.rst", "*.txt", "*.html", "*.htm", "*.css", "*.xml", "*.svg", "*.png", "*.jpg",
    "*.jpeg", "*.gif", "*.webp", "*.ico", "*.mp3", "*.ogg", "*.mp4", "*.webm", "*.pdf",
    "*.zip", "*.gz", "*.xz", "*.zst", "*.bz2", "*.tar", "*.deb", "*.rpm", "*.po", "*.mo",
    "*.json", "*.sqlite", "*.db", "*.ttf", "*.otf", "*.woff", "*.woff2", "*.cmake", "*.log",
};

/* Recognised by name (whatever the size). Patterns are matched against the
 * base name, or against the path relative to home when they contain '/'. */
static const struct { const char *pattern; const char *reason; } by_name[] = {
    { "*.kdbx",              "keepass" },
    { "*.kdb",               "keepass" },
    { "*.p12",               "pkcs12" },
    { "*.pfx",               "pkcs12" },
    { "*.jks",               "java-keystore" },
    { "*.keystore",          "java-keystore" },
    { "wallet.dat",          "crypto-wallet" },
    { ".netrc",              "netrc" },
    { ".pgpass",             "pgpass" },
    { ".my.cnf",             "mysql-client" },
    { ".git-credentials",    "git-credentials" },
    { ".aws/credentials",    "aws-credentials" },
    { ".kube/config",        "kube-config" },
    { ".docker/config.json", "docker-auth" },
    { ".config/gh/hosts.yml", "github-cli" },
    { ".config/rclone/rclone.conf", "rclone" },
    { ".gnupg/secring.gpg",  "gnupg1-secret" },
    { ".gnupg/private-keys-v1.d/*", "gnupg-private-key" },
    { ".local/share/keyrings/*.keyring", "gnome-keyring" },
    { ".local/share/kwalletd/*.kwl", "kwallet" },
    { ".password-store/*.gpg", "pass" },
    { ".password-store/*/*.gpg", "pass" },
    { "key4.db",             "browser-passwords" },
    { "logins.json",         "browser-passwords" },
    { "Login Data",          "browser-passwords" },
};

/* Recognised by content in the first MAX_SNIFF bytes: an armored private
 * key (PEM, OpenSSH, PGP) as a key file has it, with the BEGIN line at the
 * start of a line, a body of base64, and the matching END line, so source
 * code and documentation that only mention the markers do not count. PuTTY
 * and GnuPG key files are recognised by their first bytes. */
static const struct { const char *prefix; const char *reason; } by_start[] = {
    { "PuTTY-User-Key-File-",      "putty-private-key" },
    { "(21:protected-private-key", "gnupg-private-key" },
    { "(11:private-key",           "gnupg-private-key" },
};

typedef struct {
    uid_t uid;
    dev_t dev;
    gaudit_secret_fn fn;
    void *ctx;
    gaudit_secret_stats *stats;
    unsigned entries;
    char rel[PATH_MAX];
} walker;

static int matches(const char *pattern, const char *rel, const char *name)
{
    return fnmatch(pattern, strchr(pattern, '/') != NULL ? rel : name, FNM_PATHNAME) == 0;
}

static int skipped_dir(const char *rel, const char *name)
{
    for (size_t i = 0; i < sizeof skip_dirs / sizeof skip_dirs[0]; i++)
        if (matches(skip_dirs[i], rel, name))
            return 1;
    return 0;
}

static int no_sniff_name(const char *name)
{
    for (size_t i = 0; i < sizeof no_sniff / sizeof no_sniff[0]; i++)
        if (fnmatch(no_sniff[i], name, 0) == 0)
            return 1;
    return 0;
}

static const char *name_reason(const char *rel, const char *name)
{
    for (size_t i = 0; i < sizeof by_name / sizeof by_name[0]; i++)
        if (matches(by_name[i].pattern, rel, name))
            return by_name[i].reason;
    return NULL;
}

static const char *memfind(const char *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    for (size_t i = 0; m <= n && i <= n - m; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, m) == 0)
            return hay + i;
    return NULL;
}

static int is_base64(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
           || c == '+' || c == '/' || c == '=';
}

/* The reason for the first armored private key in buf, or NULL. */
static const char *armored_key(const char *buf, size_t n)
{
    static const char begin[] = "-----BEGIN ";
    const char *end = buf + n;
    for (const char *p = memfind(buf, n, begin); p != NULL;
         p = memfind(p + 1, (size_t)(end - p - 1), begin)) {
        if (p != buf && p[-1] != '\n')
            continue;
        /* The label up to the closing dashes, on the same line. */
        const char *label = p + sizeof begin - 1;
        const char *eol = memchr(label, '\n', (size_t)(end - label));
        if (eol == NULL)
            break;
        const char *close = eol - (eol > label && eol[-1] == '\r' ? 1 : 0) - 5;
        if (close <= label || memcmp(close, "-----", 5) != 0)
            continue;
        size_t len = (size_t)(close - label);
        static const char pk[] = "PRIVATE KEY", pgp[] = "PGP PRIVATE KEY BLOCK";
        int is_pgp = len == sizeof pgp - 1 && memcmp(label, pgp, len) == 0;
        if (!is_pgp && !(len >= sizeof pk - 1 && memcmp(close - (sizeof pk - 1), pk, sizeof pk - 1) == 0))
            continue;
        /* Skip header lines (Proc-Type:, Version:, ...) and blank lines,
         * then expect a line of at least 20 base64 characters. */
        const char *line = eol + 1;
        int ok = 0;
        while (line < end) {
            const char *le = memchr(line, '\n', (size_t)(end - line));
            if (le == NULL)
                break;
            size_t ll = (size_t)(le - line);
            if (ll > 0 && line[ll - 1] == '\r')
                ll--;
            if (ll == 0 || memchr(line, ':', ll) != NULL) {
                line = le + 1;
                continue;
            }
            size_t b = 0;
            while (b < ll && is_base64(line[b]))
                b++;
            ok = b == ll && ll >= 20;
            break;
        }
        if (!ok)
            continue;
        /* And the matching END line further on, at the start of a line. */
        char want[96];
        int wn = snprintf(want, sizeof want, "\n-----END %.*s-----", (int)len, label);
        if (wn < 0 || (size_t)wn >= sizeof want || memfind(eol, (size_t)(end - eol), want) == NULL)
            continue;
        if (is_pgp)
            return "pgp-private-key";
        if (len == 19 && memcmp(label, "OPENSSH PRIVATE KEY", 19) == 0)
            return "openssh-private-key";
        return "pem-private-key";
    }
    return NULL;
}

static const char *content_reason(int at_fd, const char *name, unsigned *read_count)
{
    int fd = openat(at_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return NULL;
    struct stat sb;
    static char buf[MAX_SNIFF];
    size_t used = 0;
    if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode)) {
        while (used < sizeof buf) {
            ssize_t n = read(fd, buf + used, sizeof buf - used);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            used += (size_t)n;
        }
        (*read_count)++;
    }
    close(fd);
    for (size_t i = 0; i < sizeof by_start / sizeof by_start[0]; i++) {
        size_t m = strlen(by_start[i].prefix);
        if (used >= m && memcmp(buf, by_start[i].prefix, m) == 0)
            return by_start[i].reason;
    }
    return armored_key(buf, used);
}

/* group_path/other_path: whether group and others can traverse every
 * folder from home to here. Simplified: a group member is judged by the
 * group bits only, as the kernel does, but the groups of the folders on the
 * way are not compared. */
static gaudit_reach reach_of(mode_t mode, int group_path, int other_path)
{
    if (other_path && (mode & S_IROTH))
        return GAUDIT_REACH_OTHERS;
    if (group_path && (mode & S_IRGRP))
        return GAUDIT_REACH_GROUP;
    return GAUDIT_REACH_OWNER;
}

static void walk(walker *w, int dir_fd, size_t rel_len, int depth, int group_path, int other_path)
{
    DIR *d = fdopendir(dir_fd);
    if (d == NULL) {
        close(dir_fd);
        return;
    }
    w->stats->dirs++;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        if (++w->entries > MAX_ENTRIES) {
            w->stats->truncated = 1;
            break;
        }
        int n = snprintf(w->rel + rel_len, sizeof w->rel - rel_len, "%s%s",
                         rel_len > 0 ? "/" : "", name);
        if (n < 0 || (size_t)n >= sizeof w->rel - rel_len)
            continue;
        size_t len = rel_len + (size_t)n;

        struct stat sb;
        if (fstatat(dirfd(d), name, &sb, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        if (S_ISDIR(sb.st_mode)) {
            if (sb.st_dev != w->dev || depth >= MAX_DEPTH || skipped_dir(w->rel, name)) {
                w->stats->skipped++;
                continue;
            }
            int fd = openat(dirfd(d), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd >= 0)
                walk(w, fd, len, depth + 1,
                     group_path && (sb.st_mode & S_IXGRP), other_path && (sb.st_mode & S_IXOTH));
            continue;
        }
        if (!S_ISREG(sb.st_mode))
            continue;
        w->stats->files++;
        const char *reason = name_reason(w->rel, name);
        if (reason == NULL && sb.st_size > 0 && sb.st_size <= MAX_SNIFF && !no_sniff_name(name))
            reason = content_reason(dirfd(d), name, &w->stats->read);
        if (reason == NULL)
            continue;
        gaudit_secret_hit hit = {
            .rel = w->rel, .reason = reason, .mode = sb.st_mode & 07777,
            .owned = sb.st_uid == w->uid, .gid = sb.st_gid,
            .reach = reach_of(sb.st_mode, group_path, other_path),
        };
        w->fn(&hit, w->ctx);
    }
    w->rel[rel_len] = '\0';
    closedir(d);
}

int gaudit_secret_scan(const char *home, uid_t uid, gaudit_secret_fn fn, void *ctx,
                       gaudit_secret_stats *stats)
{
    gaudit_secret_stats dummy;
    if (stats == NULL)
        stats = &dummy;
    memset(stats, 0, sizeof *stats);
    if (home == NULL || home[0] != '/' || fn == NULL)
        return -1;
    int fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat sb;
    if (fd < 0)
        return -1;
    if (fstat(fd, &sb) != 0) {
        close(fd);
        return -1;
    }
    walker w = { .uid = uid, .dev = sb.st_dev, .fn = fn, .ctx = ctx, .stats = stats };
    w.rel[0] = '\0';
    walk(&w, fd, 0, 0, (sb.st_mode & S_IXGRP) != 0, (sb.st_mode & S_IXOTH) != 0);
    return 0;
}
