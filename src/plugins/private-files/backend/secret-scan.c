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
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_DEPTH    12
#define MAX_ENTRIES  500000
/* Files up to the read limit are opened and their start read; larger ones
 * are only judged by name. Key files are small, so the limit only trades
 * speed (on large, slow disks) against keys pasted into large files. */
#define MAX_SNIFF    GAUDIT_SECRET_READ_LIMIT_MAX
static size_t read_limit = GAUDIT_SECRET_READ_LIMIT_DEFAULT;

size_t gaudit_secret_scan_read_limit(void)
{
    return read_limit;
}

int gaudit_secret_scan_set_read_limit(size_t bytes)
{
    static const size_t allowed[] = GAUDIT_SECRET_READ_LIMITS;
    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++)
        if (allowed[i] == bytes) {
            read_limit = bytes;
            return 0;
        }
    return -1;
}

/* Folders that are large, rebuilt by tools, and practically never hold
 * secrets of their own. Trash is deliberately not here: a discarded key is
 * still a key. */
/* Program code and packages: always left out (installed software, not the
 * user's data). */
static const char *const skip_dirs[] = {
    "node_modules", ".git", ".hg", ".svn", ".npm", ".cargo/registry",
    ".rustup", ".m2/repository", ".gradle/caches", "go/pkg", ".local/share/flatpak",
    ".local/share/Steam/steamapps",
    ".steam", ".wine/drive_c/windows", ".local/lib/python*", ".pyenv", ".nvm",
    ".vscode/extensions", "site-packages", "__pycache__",
    ".rbenv", ".poetry", ".local/share/pypoetry", ".local/share/containers/storage",
    ".flatpak-builder",
};

/* Caches: rebuildable, and seldom hold a key, so left out unless the full
 * run asks for them (a known list is also where something could hide one).
 * Names of their own match anywhere, also in copies of home folders from
 * Linux, Windows and macOS. */
static const char *const cache_dirs[] = {
    ".cache", ".var/app/*/cache", "snap/*/*/.cache", ".mozilla/firefox/*/cache2",
    ".config/*/Cache", ".config/*/Code Cache", ".config/*/GPUCache",
    "cache2", "Cache_Data", "Code Cache", "GPUCache", "DawnCache", "GrShaderCache", "ShaderCache",
    "Service Worker", "INetCache", "Temporary Internet Files", "CachedData",
};

static int with_caches;

void gaudit_secret_scan_set_caches(int search)
{
    with_caches = search != 0;
}

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

static gaudit_secret_progress_fn progress_fn;
static void *progress_ctx;

void gaudit_secret_scan_set_progress(gaudit_secret_progress_fn fn, void *ctx)
{
    progress_fn = fn;
    progress_ctx = ctx;
}

typedef struct {
    uid_t uid;
    dev_t dev;
    gaudit_secret_fn fn;
    void *ctx;
    gaudit_secret_stats *stats;
    unsigned entries;
    char rel[PATH_MAX];
} walker;

/* A pattern without '/' is matched against the name, anywhere. One with
 * '/' against the path, from the root or from any folder boundary in it,
 * so the Flatpak cache pattern also catches a copied home folder's, however
 * deep the copy lies (fnmatch has no double star). */
static int matches(const char *pattern, const char *rel, const char *name)
{
    if (strchr(pattern, '/') == NULL)
        return fnmatch(pattern, name, FNM_PATHNAME) == 0;
    for (const char *p = rel; p != NULL; p = strchr(p, '/')) {
        if (*p == '/')
            p++;
        if (fnmatch(pattern, p, FNM_PATHNAME) == 0)
            return 1;
    }
    return 0;
}

/* 1 program code or packages, 2 a cache left out, 0 searched. */
static int skipped_dir(const char *rel, const char *name)
{
    for (size_t i = 0; i < sizeof skip_dirs / sizeof skip_dirs[0]; i++)
        if (matches(skip_dirs[i], rel, name))
            return 1;
    for (size_t i = 0; !with_caches && i < sizeof cache_dirs / sizeof cache_dirs[0]; i++)
        if (matches(cache_dirs[i], rel, name))
            return 2;
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

/* Names of key files the scan knows by their content; used only where the
 * content cannot be read. .pem and .key may hold a certificate or a public
 * key instead, so they are "probably". */
static const struct { const char *pattern; const char *reason; } by_name_only[] = {
    { "id_rsa",          "ssh-key-name" },
    { "id_dsa",          "ssh-key-name" },
    { "id_ecdsa",        "ssh-key-name" },
    { "id_ecdsa_sk",     "ssh-key-name" },
    { "id_ed25519",      "ssh-key-name" },
    { "id_ed25519_sk",   "ssh-key-name" },
    { "*.ppk",           "putty-private-key" },
    { "*.pem",           "key-file-name" },
    { "*.key",           "key-file-name" },
};

const char *gaudit_secret_reason_by_name(const char *rel, int name_only)
{
    if (rel == NULL || rel[0] == '\0')
        return NULL;
    const char *name = strrchr(rel, '/');
    name = name != NULL ? name + 1 : rel;
    if (name[0] == '\0')
        return NULL;
    const char *r = name_reason(rel, name);
    for (size_t i = 0; r == NULL && name_only && i < sizeof by_name_only / sizeof by_name_only[0]; i++)
        if (fnmatch(by_name_only[i].pattern, name, 0) == 0)
            r = by_name_only[i].reason;
    return r;
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
        while (used < read_limit) {
            ssize_t n = read(fd, buf + used, read_limit - used);
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
        /* Often enough to move steadily on a slow disk; the caller only
         * passes it on every two seconds. */
        if ((++w->entries & 255) == 0 && progress_fn != NULL)
        {
            char saved = w->rel[rel_len];
            w->rel[rel_len] = '\0';  /* the folder, not the entry in it */
            progress_fn(w->entries, w->rel, progress_ctx);
            w->rel[rel_len] = saved;
        }
        if (w->entries > MAX_ENTRIES) {
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
            int skip = sb.st_dev != w->dev || depth >= MAX_DEPTH ? 1 : skipped_dir(w->rel, name);
            if (skip != 0) {
                w->stats->skipped++;
                if (skip == 2)
                    w->stats->caches++;
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
        if (reason == NULL && sb.st_size > 0 && (size_t)sb.st_size <= read_limit && !no_sniff_name(name))
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

/* Walks root; group and others reach it only if from_group/from_other
 * (the folders above it let them through). */
static int scan_from(const char *root, uid_t uid, int from_group, int from_other,
                     gaudit_secret_fn fn, void *ctx, gaudit_secret_stats *stats)
{
    gaudit_secret_stats dummy;
    if (stats == NULL)
        stats = &dummy;
    memset(stats, 0, sizeof *stats);
    if (root == NULL || root[0] != '/' || fn == NULL)
        return -1;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat sb;
    if (fd < 0)
        return -1;
    if (fstat(fd, &sb) != 0) {
        close(fd);
        return -1;
    }
    walker w = { .uid = uid, .dev = sb.st_dev, .fn = fn, .ctx = ctx, .stats = stats };
    w.rel[0] = '\0';
    walk(&w, fd, 0, 0, from_group && (sb.st_mode & S_IXGRP) != 0,
         from_other && (sb.st_mode & S_IXOTH) != 0);
    return 0;
}

int gaudit_secret_scan(const char *home, uid_t uid, gaudit_secret_fn fn, void *ctx,
                       gaudit_secret_stats *stats)
{
    /* The home folder is judged from itself down. */
    return scan_from(home, uid, 1, 1, fn, ctx, stats);
}

/* Whether group and others can get through every folder above root, from
 * "/" down (looked at, never listed). -1 if one cannot be looked at. */
static int above_root(const char *root, int *group, int *other)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s", root) >= (int)sizeof path)
        return -1;
    *group = 1;
    *other = 1;
    for (char *slash = strrchr(path, '/'); slash != NULL; slash = strrchr(path, '/')) {
        *slash = '\0';
        struct stat sb;
        if (stat(path[0] != '\0' ? path : "/", &sb) != 0)
            return -1;
        *group = *group && (sb.st_mode & S_IXGRP) != 0;
        *other = *other && (sb.st_mode & S_IXOTH) != 0;
        if (path[0] == '\0')
            break;
    }
    return 0;
}

int gaudit_secret_scan_area(const char *root, uid_t uid, gaudit_secret_fn fn, void *ctx,
                            gaudit_secret_stats *stats)
{
    if (root == NULL || root[0] != '/')
        return -1;
    /* The folders above root: a closed one protects everything below it. */
    int group, other;
    if (above_root(root, &group, &other) != 0)
        return -1;
    return scan_from(root, uid, group, other, fn, ctx, stats);
}

/* rel's folder beneath root_fd, no symbolic link on the way, and whether
 * group and others get through every folder from root down to it. */
static int open_folder(int root_fd, const char *rel, int *group, int *other)
{
    int fd = dup(root_fd);
    char part[PATH_MAX];
    const char *p = rel;
    for (const char *slash = strchr(p, '/'); fd >= 0 && slash != NULL; slash = strchr(p, '/')) {
        size_t n = (size_t)(slash - p);
        if (n == 0 || n >= sizeof part) {
            close(fd);
            return -1;
        }
        memcpy(part, p, n);
        part[n] = '\0';
        struct open_how how = { .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
                                .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS };
        int next = (int)syscall(SYS_openat2, fd, part, &how, sizeof how);
        close(fd);
        fd = next;
        struct stat sb;
        if (fd < 0 || fstat(fd, &sb) != 0) {
            if (fd >= 0)
                close(fd);
            return -1;
        }
        *group = *group && (sb.st_mode & S_IXGRP) != 0;
        *other = *other && (sb.st_mode & S_IXOTH) != 0;
        p = slash + 1;
    }
    return fd;
}

int gaudit_secret_check_one(const char *root, int outside_home, const char *rel, uid_t uid,
                            gaudit_secret_hit *out)
{
    if (root == NULL || root[0] != '/' || rel == NULL || rel[0] == '\0' || rel[0] == '/'
        || strstr(rel, "..") != NULL || out == NULL)
        return -1;
    int group = 1, other = 1;
    if (outside_home && above_root(root, &group, &other) != 0)
        return -1;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat sb;
    if (root_fd < 0 || fstat(root_fd, &sb) != 0) {
        if (root_fd >= 0)
            close(root_fd);
        return -1;
    }
    group = group && (sb.st_mode & S_IXGRP) != 0;
    other = other && (sb.st_mode & S_IXOTH) != 0;
    int dir = open_folder(root_fd, rel, &group, &other);
    close(root_fd);
    if (dir < 0)
        return 0;  /* gone, or no longer reached the same way */
    const char *name = strrchr(rel, '/') != NULL ? strrchr(rel, '/') + 1 : rel;
    int found = 0;
    if (fstatat(dir, name, &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(sb.st_mode)) {
        const char *reason = name_reason(rel, name);
        unsigned reads = 0;
        if (reason == NULL && sb.st_size > 0 && (size_t)sb.st_size <= read_limit && !no_sniff_name(name))
            reason = content_reason(dir, name, &reads);
        if (reason != NULL) {
            *out = (gaudit_secret_hit){
                .rel = rel, .reason = reason, .mode = sb.st_mode & 07777,
                .owned = sb.st_uid == uid, .gid = sb.st_gid,
                .reach = reach_of(sb.st_mode, group, other),
            };
            found = 1;
        }
    }
    close(dir);
    return found;
}
