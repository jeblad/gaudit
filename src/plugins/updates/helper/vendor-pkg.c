/* SPDX-License-Identifier: GPL-3.0-only */
#include "vendor-pkg.h"

#include "apt.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "vendor.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/openat2.h>

#define MAX_PACKAGE (1024ULL * 1024 * 1024)  /* 1 GiB: Zoom's is about 300 MB */
#define MAX_SIG     (64 * 1024)
#define MAX_PARTS   8

/* --- Small pieces --------------------------------------------------------- */

static void path_in(const gaudit_vendor_env *env, const char *id, const char *ext, char *out,
                    size_t len)
{
    snprintf(out, len, "%s/%s%s", env->cache_dir, id, ext);
}

/* dir exists as a folder owned by env->owner, not writable by others;
 * made with mode when missing. 0 on success. */
static int ensure_dir(const char *dir, mode_t mode, uid_t owner)
{
    if (mkdir(dir, mode) != 0 && errno != EEXIST)
        return -1;
    struct stat st;
    return lstat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == owner
           && (st.st_mode & 022) == 0 ? 0 : -1;
}

/* Its parent (made 0755) and itself (made 0700). */
static int ensure_cache(const gaudit_vendor_env *env)
{
    char parent[512];
    snprintf(parent, sizeof parent, "%s", env->cache_dir);
    char *slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent)
        return -1;
    *slash = '\0';
    return ensure_dir(parent, 0755, env->owner) == 0 && ensure_dir(env->cache_dir, 0700, env->owner) == 0
           ? 0 : -1;
}

static void clean_dir(int dfd)
{
    DIR *d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            int sub = openat(dirfd(d), de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub >= 0)
                clean_dir(sub);
            unlinkat(dirfd(d), de->d_name, AT_REMOVEDIR);
        } else {
            unlinkat(dirfd(d), de->d_name, 0);
        }
    }
    closedir(d);
}

void gaudit_vendor_clean(const gaudit_vendor_env *env)
{
    if (env == NULL || env->cache_dir == NULL)
        return;
    int dfd = open(env->cache_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd >= 0)
        clean_dir(dfd);
    rmdir(env->cache_dir);  /* an empty folder leaves no trace */
}

/* Runs argv with a fixed environment (plus extra, NULL for none), its
 * stdout and stderr together into out (at most len - 1 bytes). The exit
 * status, or -1. */
static int run_capture_env(char *const argv[], const char *extra, char *out, size_t len,
                           long timeout_ms)
{
    char *env[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", (char *)"LC_ALL=C", (char *)"HOME=/root",
        (char *)extra, NULL,
    };
    int fds[2];
    if (out == NULL || len == 0 || pipe2(fds, O_CLOEXEC) != 0)
        return -1;
    out[0] = '\0';
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(fds[1], STDOUT_FILENO) < 0
            || dup2(fds[1], STDERR_FILENO) < 0 || chdir("/") != 0)
            _exit(126);
        execve(argv[0], argv, env);
        _exit(127);
    }
    close(fds[1]);
    size_t used = 0;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = timeout_ms - (long)((now.tv_sec - start.tv_sec) * 1000
                                        + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) {
            kill(pid, SIGKILL);
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        int r = poll(&pfd, 1, (int)left);
        if (r <= 0)
            continue;
        char chunk[1024];
        ssize_t n = read(fds[0], chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        size_t take = (size_t)n < len - 1 - used ? (size_t)n : len - 1 - used;
        memcpy(out + used, chunk, take);
        used += take;
    }
    out[used] = '\0';
    close(fds[0]);
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_capture(char *const argv[], char *out, size_t len, long timeout_ms)
{
    return run_capture_env(argv, NULL, out, len, timeout_ms);
}

/* --- The signature -------------------------------------------------------- */

static int hex_of(const char *s, size_t n)
{
    if (strlen(s) != n)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

int gaudit_vendor_listed_parts(const char *text, gaudit_vendor_part *parts, size_t max)
{
    if (text == NULL || parts == NULL)
        return -1;
    int role = 0, files = 0, n = 0;
    for (const char *p = text; *p != '\0';) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl != NULL ? (size_t)(nl - p) : strlen(p);
        char line[512];
        if (ll >= sizeof line)
            return -1;
        memcpy(line, p, ll);
        line[ll] = '\0';
        p += ll + (nl != NULL);
        if (files && line[0] == '\t') {
            gaudit_vendor_part part;
            char size[32];
            if ((size_t)n >= max
                || sscanf(line + 1, "%32s %40s %31s %63s", part.md5, part.sha1, size, part.name) != 4
                || !hex_of(part.md5, 32) || !hex_of(part.sha1, 40) || size[0] == '-')
                return -1;
            char *e;
            errno = 0;
            part.size = strtoull(size, &e, 10);
            if (errno != 0 || *e != '\0' || e == size)
                return -1;
            for (int i = 0; i < n; i++)
                if (strcmp(parts[i].name, part.name) == 0)
                    return -1;  /* each part once */
            parts[n++] = part;
            continue;
        }
        files = 0;
        if (strncmp(line, "Files:", 6) == 0)
            files = 1;
        else if (strcmp(line, "Role: builder") == 0)
            role = 1;
    }
    return role && n > 0 ? n : -1;
}

int gaudit_vendor_sqv_result(int exit_status, const char *output, char fingerprint[41])
{
    if (output == NULL || fingerprint == NULL)
        return -1;
    fingerprint[0] = '\0';
    if (exit_status != 0)
        return strstr(output, "Missing key") != NULL ? -2 : -1;
    /* On success sqv names the key of each good signature, one per line:
     * exactly one, and nothing else that looks like a key. */
    int keys = 0;
    for (const char *p = output; *p != '\0';) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl != NULL ? (size_t)(nl - p) : strlen(p);
        int hex = ll == 40;
        for (size_t i = 0; hex && i < 40; i++)
            hex = (p[i] >= '0' && p[i] <= '9') || (p[i] >= 'A' && p[i] <= 'F');
        if (hex) {
            memcpy(fingerprint, p, 40);
            fingerprint[40] = '\0';
            keys++;
        }
        p += ll + (nl != NULL);
    }
    if (keys != 1) {
        fingerprint[0] = '\0';
        return -1;
    }
    return 0;
}

int gaudit_vendor_sqv_check(const gaudit_vendor_env *env, const char *key, const char *sigf,
                            const char *textf, char fpr[41], int *weak)
{
    /* sqv, strict first: a signature its default policy accepts is
     * verified; one it accepts only when SHA-1 is allowed is weak, and the
     * user's choice; anything else is refused. Only what sqv authenticated
     * is read on: the key's fingerprint it names, and the text it wrote
     * (which it may write even when it refuses, so only on success). */
    char said[4096];
    char *sqv[] = {
        (char *)env->sqv, (char *)"--keyring", (char *)key, (char *)"--output", (char *)textf,
        (char *)"--cleartext", (char *)sigf, NULL,
    };
    *weak = 0;
    unlink(textf);
    int st = gaudit_vendor_sqv_result(run_capture(sqv, said, sizeof said, 60 * 1000), said, fpr);
    if (st == -1) {
        char policy[700];
        snprintf(policy, sizeof policy, "SEQUOIA_CRYPTO_POLICY=%s", env->weak_policy);
        unlink(textf);
        st = gaudit_vendor_sqv_result(run_capture_env(sqv, policy, said, sizeof said, 60 * 1000),
                                      said, fpr);
        *weak = st == 0;
    }
    if (st != 0)
        unlink(textf);
    return st;
}

/* --- Checking ------------------------------------------------------------- */

static int open_beneath_nolinks(const char *path)
{
    struct open_how how = { .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
                            .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
    /* No fallback: without openat2 (Linux before 5.6), O_NOFOLLOW would
     * stop only a link in the last part, and root would follow the user's
     * links on the way. Every release gAudit supports has openat2. */
    long fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof how);
    return (int)fd;
}

/* Copies src into dst (made new, 0600). 0, or a result name. */
static const char *copy_in(const char *src, const char *dst)
{
    int in = open_beneath_nolinks(src);
    if (in < 0)
        return "no-file";
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(in);
        return "no-file";
    }
    if ((unsigned long long)st.st_size > MAX_PACKAGE) {
        close(in);
        return "too-large";
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) {
        close(in);
        return "error";
    }
    static char buf[1 << 16];
    unsigned long long total = 0;
    const char *result = NULL;
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            result = "error";
            break;
        }
        if (n == 0)
            break;
        total += (unsigned long long)n;
        if (total > MAX_PACKAGE) {
            result = "too-large";
            break;
        }
        for (ssize_t off = 0; off < n;) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                result = "error";
                break;
            }
            off += w;
        }
        if (result != NULL)
            break;
    }
    close(in);
    if (fsync(out) != 0 && result == NULL)
        result = "error";
    close(out);
    return result;
}

static int read_full(int fd, void *buf, size_t len)
{
    for (size_t got = 0; got < len;) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

/* The ar archive at path: every member but _gpgbuilder digested into
 * parts, _gpgbuilder into sig. 0 on success, -1 when it is not a package
 * with exactly the parts expected. */
static int scan_package(const char *path, gaudit_vendor_part *parts, int *n_parts, char *sig,
                        size_t *sig_len)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char magic[8];
    int ok = read_full(fd, magic, 8) == 0 && memcmp(magic, "!<arch>\n", 8) == 0;
    *n_parts = 0;
    *sig_len = 0;
    int have_sig = 0;
    static char buf[1 << 16];
    while (ok) {
        char h[60];
        ssize_t first = read(fd, h, 1);
        if (first == 0)
            break;  /* the end */
        if (first != 1 || read_full(fd, h + 1, 59) != 0 || h[58] != '`' || h[59] != '\n') {
            ok = 0;
            break;
        }
        char name[17], size_s[11];
        memcpy(name, h, 16);
        name[16] = '\0';
        for (int i = 15; i >= 0 && (name[i] == ' ' || name[i] == '/'); i--)
            name[i] = '\0';
        memcpy(size_s, h + 48, 10);
        size_s[10] = '\0';
        char *e;
        errno = 0;
        unsigned long long size = strtoull(size_s, &e, 10);
        while (*e == ' ')
            e++;
        if (errno != 0 || *e != '\0' || size_s[0] == ' ' || size > MAX_PACKAGE) {
            ok = 0;
            break;
        }
        int is_sig = strcmp(name, "_gpgbuilder") == 0;
        int known = is_sig || strcmp(name, "debian-binary") == 0
                    || strncmp(name, "control.tar", 11) == 0 || strncmp(name, "data.tar", 8) == 0;
        if (!known || (is_sig && (have_sig || size > MAX_SIG)) || (!is_sig && *n_parts >= MAX_PARTS)) {
            ok = 0;
            break;
        }
        for (int i = 0; i < *n_parts; i++)
            if (strcmp(parts[i].name, name) == 0)
                ok = 0;
        if (!ok)
            break;
        if (is_sig) {
            if (read_full(fd, sig, (size_t)size) != 0) {
                ok = 0;
                break;
            }
            *sig_len = (size_t)size;
            have_sig = 1;
        } else {
            gaudit_md5 md5;
            gaudit_sha1 sha1;
            gaudit_md5_init(&md5);
            gaudit_sha1_init(&sha1);
            for (unsigned long long left = size; left > 0;) {
                size_t take = left < sizeof buf ? (size_t)left : sizeof buf;
                if (read_full(fd, buf, take) != 0) {
                    ok = 0;
                    break;
                }
                gaudit_md5_update(&md5, buf, take);
                gaudit_sha1_update(&sha1, buf, take);
                left -= take;
            }
            if (!ok)
                break;
            gaudit_vendor_part *p = &parts[(*n_parts)++];
            snprintf(p->name, sizeof p->name, "%s", name);
            p->size = size;
            unsigned char d5[16], d1[20];
            gaudit_md5_final(&md5, d5);
            gaudit_sha1_final(&sha1, d1);
            gaudit_md5_hex(d5, p->md5);
            gaudit_sha1_hex(d1, p->sha1);
        }
        if (size % 2 == 1) {
            char pad;
            if (read_full(fd, &pad, 1) != 0) {
                ok = 0;
                break;
            }
        }
    }
    close(fd);
    return ok && have_sig && *n_parts >= 3 ? 0 : (ok && !have_sig ? -2 : -1);
}

static int file_sha256(const char *path, char hex[65])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    gaudit_sha256 ctx;
    gaudit_sha256_init(&ctx);
    static char buf[1 << 16];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        gaudit_sha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    unsigned char d[32];
    gaudit_sha256_final(&ctx, d);
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", d[i]);
    return 0;
}

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    size_t len = strlen(text);
    int ok = write(fd, text, len) == (ssize_t)len;
    close(fd);
    return ok ? 0 : -1;
}

void gaudit_vendor_verify(const gaudit_vendor_env *env, const char *id, const char *version,
                          const char *path, gaudit_vendor_outcome *out)
{
    memset(out, 0, sizeof *out);
    out->result = "error";
    const gaudit_vendor_package *v = gaudit_vendor_find(id);
    if (env == NULL || !gaudit_vendor_verify_args_ok(id, version, path) || v == NULL)
        return;
    snprintf(out->version, sizeof out->version, "%s", version);
    /* Nothing from before: one package at a time, checked from scratch. */
    gaudit_vendor_clean(env);
    if (ensure_cache(env) != 0)
        return;
    char deb[640], sigf[640], textf[640], ok_file[640], key[640];
    path_in(env, id, ".deb", deb, sizeof deb);
    path_in(env, id, ".sig", sigf, sizeof sigf);
    path_in(env, id, ".txt", textf, sizeof textf);
    path_in(env, id, ".ok", ok_file, sizeof ok_file);
    snprintf(key, sizeof key, "%s/%s", env->keys_dir, v->key_file);

    const char *copied = copy_in(path, deb);
    if (copied != NULL) {
        out->result = copied;
        return;
    }
    gaudit_vendor_part parts[MAX_PARTS], listed[MAX_PARTS];
    int n_parts = 0;
    static char sig[MAX_SIG + 1];
    size_t sig_len = 0;
    int scanned = scan_package(deb, parts, &n_parts, sig, &sig_len);
    if (scanned != 0) {
        out->result = scanned == -2 ? "not-signed" : "mismatch";
        return;
    }
    sig[sig_len] = '\0';

    /* The key file: gAudit's own, never one anyone else could change. */
    struct stat kst;
    if (lstat(key, &kst) != 0 || !S_ISREG(kst.st_mode) || (kst.st_mode & 022) != 0
        || (env->check_key_owner && kst.st_uid != 0))
        return;
    /* The policy that allows SHA-1, gAudit's own as the key file is. */
    struct stat pst;
    if (lstat(env->weak_policy, &pst) != 0 || !S_ISREG(pst.st_mode) || (pst.st_mode & 022) != 0
        || (env->check_key_owner && pst.st_uid != 0))
        return;
    if (write_text(sigf, sig) != 0)
        return;
    char fpr[41];
    int weak = 0;
    int st = gaudit_vendor_sqv_check(env, key, sigf, textf, fpr, &weak);
    if (st == -2) {
        out->result = "unknown-key";
        return;
    }
    if (st != 0) {
        out->result = "bad-signature";
        return;
    }
    /* The key gAudit vouches for, by its fingerprint. */
    int vouched = 0;
    for (size_t i = 0; i < v->n_keys; i++)
        vouched |= strcmp(v->keys[i].fingerprint, fpr) == 0;
    if (!vouched) {
        out->result = "unknown-key";
        return;
    }
    if (weak)
        snprintf(out->hash, sizeof out->hash, "%s", "SHA1");  /* the only thing the policy allows */

    /* Every part, as the authenticated text lists it; nothing more, nothing less. */
    static char text[MAX_SIG + 1];
    int tfd = open(textf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    ssize_t tn = tfd >= 0 ? read(tfd, text, sizeof text - 1) : -1;
    if (tfd >= 0)
        close(tfd);
    if (tn < 0) {
        out->result = "mismatch";
        return;
    }
    text[tn] = '\0';
    int n_listed = gaudit_vendor_listed_parts(text, listed, MAX_PARTS);
    if (n_listed != n_parts) {
        out->result = "mismatch";
        return;
    }
    for (int i = 0; i < n_parts; i++) {
        int match = 0;
        for (int j = 0; j < n_listed; j++)
            match |= strcmp(parts[i].name, listed[j].name) == 0 && strcmp(parts[i].md5, listed[j].md5) == 0
                     && strcmp(parts[i].sha1, listed[j].sha1) == 0 && parts[i].size == listed[j].size;
        if (!match) {
            out->result = "mismatch";
            return;
        }
    }

    /* The package's own name and version, and newer than the one installed. */
    char fields[512];
    char *field[] = {
        (char *)env->dpkg_deb, (char *)"--field", deb, (char *)"Package", (char *)"Version", NULL,
    };
    char want[256];
    snprintf(want, sizeof want, "Package: %s\nVersion: %s\n", v->package, version);
    if (run_capture(field, fields, sizeof fields, 60 * 1000) != 0 || strcmp(fields, want) != 0) {
        out->result = "wrong-package";
        return;
    }
    char installed[256];
    char *query[] = {
        (char *)env->dpkg_query, (char *)"-W", (char *)"-f=${Status} ${Version}", (char *)"--",
        (char *)v->package, NULL,
    };
    if (run_capture(query, installed, sizeof installed, 60 * 1000) != 0) {
        out->result = "not-newer";
        return;
    }
    char want_s[16], ok_s[16], state[32], have[200];
    if (sscanf(installed, "%15s %15s %31s %199s", want_s, ok_s, state, have) != 4
        || strcmp(state, "installed") != 0) {
        out->result = "not-newer";
        return;
    }
    char ignored[16];
    char *cmp[] = {
        (char *)env->dpkg, (char *)"--compare-versions", (char *)version, (char *)"gt", have, NULL,
    };
    if (run_capture(cmp, ignored, sizeof ignored, 60 * 1000) != 0) {
        out->result = "not-newer";
        return;
    }

    /* What install takes: these bytes, this version, whether it was weak. */
    char digest[65], mark[160];
    if (file_sha256(deb, digest) != 0)
        return;
    snprintf(mark, sizeof mark, "%s %s %d\n", digest, version, weak);
    if (write_text(ok_file, mark) != 0)
        return;
    unlink(sigf);
    unlink(textf);
    out->result = weak ? "weak" : "verified";
}

void gaudit_vendor_install(const gaudit_vendor_env *env, const char *id, int anyway,
                           gaudit_vendor_outcome *out)
{
    memset(out, 0, sizeof *out);
    out->result = "not-verified";
    const gaudit_vendor_package *v = gaudit_vendor_find(id);
    if (env == NULL || v == NULL)
        return;
    char deb[640], ok_file[640];
    path_in(env, id, ".deb", deb, sizeof deb);
    path_in(env, id, ".ok", ok_file, sizeof ok_file);
    char mark[200] = "";
    int fd = open(ok_file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, mark, sizeof mark - 1);
        mark[n > 0 ? n : 0] = '\0';
        close(fd);
    }
    char want[65], version[40], digest[65];
    int weak;
    if (sscanf(mark, "%64s %39s %d", want, version, &weak) != 3 || file_sha256(deb, digest) != 0
        || strcmp(want, digest) != 0 || (weak && !anyway)) {
        gaudit_vendor_clean(env);
        return;
    }
    snprintf(out->version, sizeof out->version, "%s", version);
    int status = gaudit_apt_install_file(deb);
    out->result = status == 0 ? "installed" : "failed";
    gaudit_vendor_clean(env);
}
