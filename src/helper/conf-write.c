/* SPDX-License-Identifier: GPL-3.0-only */
#include "conf-write.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define REGISTER_FILE "written"
#define REGISTER_NEW  ".written.new"
#define LOCK_FILE     ".lock"
#define MAX_PATH      256
#define MAX_WORD      64
_Static_assert(MAX_WORD == 64 && MAX_PATH == 256, "the register's sscanf widths");

typedef struct {
    char hex[65];
    char template_id[MAX_WORD];
    char values[MAX_WORD];
    char path[MAX_PATH];
} entry;

typedef struct {
    entry e[GAUDIT_CONF_MAX_ENTRIES];
    size_t n;
} reg;

const char *gaudit_conf_result_name(gaudit_conf_result r)
{
    static const char *const names[] = {
        "written", "unchanged", "removed", "not-there", "foreign",
        "edited", "precondition", "unsafe", "error",
    };
    return (unsigned)r < sizeof names / sizeof names[0] ? names[r] : "error";
}

/* --- Names ----------------------------------------------------------------- */

static int path_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
        || c == '.' || c == '_' || c == '-';
}

/* Relative, components of [A-Za-z0-9._-] that are neither empty nor
 * start with a dot, so no "..", no hidden names and no surprises. */
static int valid_path(const char *p)
{
    size_t len = p != NULL ? strlen(p) : 0;
    if (len == 0 || len >= MAX_PATH || p[0] == '/' || p[len - 1] == '/')
        return 0;
    int start = 1;
    for (const char *c = p; *c != '\0'; c++) {
        if (*c == '/') {
            if (start)
                return 0;
            start = 1;
            continue;
        }
        if (!path_char(*c) || (start && *c == '.'))
            return 0;
        start = 0;
    }
    return 1;
}

static int valid_word(const char *s)
{
    size_t len = s != NULL ? strlen(s) : 0;
    if (len == 0 || len >= MAX_WORD)
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '_'
              || *c == '-'))
            return 0;
    return 1;
}

static int valid_hex(const char *s)
{
    if (s == NULL || strlen(s) != 64)
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return 0;
    return 1;
}

/* --- Opening without following links ------------------------------------- */

static int open_beneath(int dirfd, const char *name, int flags, mode_t mode)
{
    struct open_how how = {
        .flags = (unsigned long long)(flags | O_CLOEXEC | O_NOFOLLOW),
        .mode = (flags & O_CREAT) ? mode : 0,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    return (int)syscall(SYS_openat2, dirfd, name, &how, sizeof how);
}

/* A folder may be used if it belongs to the owner and only the owner can
 * change what is in it. */
static int safe_dir(int fd, uid_t owner)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == owner
        && (st.st_mode & 022) == 0;
}

static int open_root(const gaudit_conf_env *env)
{
    int fd = open(env->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && !safe_dir(fd, env->owner)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* The folder dir (relative, may be "") beneath rootfd, every folder on the
 * way checked. create: make missing ones (mode 0755). -1 with *missing
 * set when a folder does not exist, -1 otherwise when it is not safe. */
static int open_dir(const gaudit_conf_env *env, int rootfd, const char *dir, int create,
                    int *missing)
{
    *missing = 0;
    int fd = dup(rootfd);
    if (fd < 0)
        return -1;
    char buf[MAX_PATH];
    snprintf(buf, sizeof buf, "%s", dir);
    char *save = NULL;
    for (char *comp = strtok_r(buf, "/", &save); comp != NULL; comp = strtok_r(NULL, "/", &save)) {
        int next = open_beneath(fd, comp, O_RDONLY | O_DIRECTORY, 0);
        if (next < 0 && errno == ENOENT && create) {
            if (mkdirat(fd, comp, 0755) != 0 && errno != EEXIST) {
                close(fd);
                return -1;
            }
            next = open_beneath(fd, comp, O_RDONLY | O_DIRECTORY, 0);
        }
        if (next < 0 && errno == ENOENT)
            *missing = 1;
        close(fd);
        if (next < 0)
            return -1;
        if (!safe_dir(next, env->owner)) {
            close(next);
            return -1;
        }
        fd = next;
    }
    return fd;
}

static void split(const char *path, char *dir, char *name)
{
    const char *slash = strrchr(path, '/');
    if (slash == NULL) {
        dir[0] = '\0';
        snprintf(name, MAX_PATH, "%s", path);
    } else {
        snprintf(dir, MAX_PATH, "%.*s", (int)(slash - path), path);
        snprintf(name, MAX_PATH, "%s", slash + 1);
    }
}

/* Reads a whole regular file beneath dirfd. 1: read (buf malloc'd, *len);
 * 0: it does not exist; -1: anything else (a link, not regular, more than
 * one name, the wrong owner, too large, unreadable). */
static int read_file(const gaudit_conf_env *env, int dirfd, const char *name, char **buf,
                     size_t *len)
{
    int fd = open_beneath(dirfd, name, O_RDONLY | O_NONBLOCK, 0);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1
        || st.st_uid != env->owner || st.st_size > GAUDIT_CONF_MAX_FILE) {
        close(fd);
        return -1;
    }
    char *b = malloc((size_t)st.st_size + 1);
    size_t used = 0;
    while (b != NULL) {
        ssize_t n = read(fd, b + used, (size_t)st.st_size + 1 - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n < 0) {
                free(b);
                b = NULL;
            }
            break;
        }
        used += (size_t)n;
        if (used > (size_t)st.st_size) {  /* grew while read */
            free(b);
            b = NULL;
        }
    }
    close(fd);
    if (b == NULL)
        return -1;
    b[used] = '\0';
    *buf = b;
    *len = used;
    return 1;
}

/* 1: exists with digest hex; 0: does not exist; -1: cannot be used. */
static int file_digest(const gaudit_conf_env *env, int dirfd, const char *name, char hex[65])
{
    char *buf;
    size_t len;
    int r = read_file(env, dirfd, name, &buf, &len);
    if (r == 1) {
        gaudit_sha256_hex(buf, len, hex);
        free(buf);
    }
    return r;
}

static int write_all(int fd, const char *p, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Writes content to tmp beneath dirfd: new, synced, with mode. */
static int write_new(int dirfd, const char *tmp, const char *content, size_t len, mode_t mode)
{
    if (unlinkat(dirfd, tmp, 0) != 0 && errno != ENOENT)  /* left by a crash; we hold the lock */
        return -1;
    int fd = open_beneath(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0)
        return -1;
    if (fchmod(fd, mode) != 0 || write_all(fd, content, len) != 0 || fsync(fd) != 0) {
        close(fd);
        unlinkat(dirfd, tmp, 0);
        return -1;
    }
    return close(fd);
}

/* --- The register ---------------------------------------------------------- */

static int load_register(const gaudit_conf_env *env, int regfd, reg *r)
{
    r->n = 0;
    if (regfd < 0)
        return 0;  /* no register folder yet: nothing written */
    char *buf;
    size_t len;
    int got = read_file(env, regfd, REGISTER_FILE, &buf, &len);
    if (got <= 0)
        return got;
    /* A file that does not end with a newline was cut short. */
    int ok = len > 0 && buf[len - 1] != '\n' ? -1 : 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); ok == 0 && line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        ok = -1;
        if (r->n >= GAUDIT_CONF_MAX_ENTRIES)
            break;
        entry *e = &r->e[r->n];
        char extra;
        /* Widths: 64 hex digits, MAX_WORD - 1, MAX_WORD - 1, MAX_PATH - 1. */
        if (sscanf(line, "%64s %63s %63s %255s %c", e->hex, e->template_id, e->values, e->path,
                   &extra) != 4
            || !valid_hex(e->hex) || !valid_word(e->template_id) || !valid_word(e->values)
            || !valid_path(e->path))
            break;
        /* Exactly one space between fields, nothing else on the line. */
        char again[65 + 2 * MAX_WORD + MAX_PATH + 4];
        snprintf(again, sizeof again, "%s %s %s %s", e->hex, e->template_id, e->values, e->path);
        if (strcmp(again, line) != 0)
            break;
        for (size_t i = 0; i < r->n; i++)
            if (strcmp(r->e[i].path, e->path) == 0)
                goto out;  /* listed twice: damaged */
        r->n++;
        ok = 0;
    }
out:
    free(buf);
    return ok;
}

static int save_register(int regfd, const reg *r)
{
    size_t cap = r->n * (MAX_PATH + 3 * MAX_WORD + 8) + 1, used = 0;
    char *out = malloc(cap);
    if (out == NULL)
        return -1;
    out[0] = '\0';
    for (size_t i = 0; i < r->n; i++)
        used += (size_t)snprintf(out + used, cap - used, "%s %s %s %s\n", r->e[i].hex,
                                 r->e[i].template_id, r->e[i].values, r->e[i].path);
    int rc = write_new(regfd, REGISTER_NEW, out, used, 0644) != 0
          || renameat(regfd, REGISTER_NEW, regfd, REGISTER_FILE) != 0 || fsync(regfd) != 0
        ? -1 : 0;
    free(out);
    return rc;
}

static entry *find(reg *r, const char *path)
{
    for (size_t i = 0; i < r->n; i++)
        if (strcmp(r->e[i].path, path) == 0)
            return &r->e[i];
    return NULL;
}

static void drop(reg *r, entry *e)
{
    size_t i = (size_t)(e - r->e);
    memmove(&r->e[i], &r->e[i + 1], (r->n - i - 1) * sizeof r->e[0]);
    r->n--;
}

/* --- Session: root, register folder, lock, register ---------------------- */

typedef struct {
    int rootfd, regfd, lockfd;
    reg r;
} session;

static void session_end(session *s)
{
    if (s->lockfd >= 0)
        close(s->lockfd);  /* releases the lock */
    if (s->regfd >= 0)
        close(s->regfd);
    if (s->rootfd >= 0)
        close(s->rootfd);
}

/* create: make the register folder if needed (only when writing). */
static gaudit_conf_result session_begin(const gaudit_conf_env *env, int create, session *s)
{
    s->rootfd = s->regfd = s->lockfd = -1;
    if (env == NULL || env->root == NULL || !valid_path(env->register_dir))
        return GAUDIT_CONF_ERROR;
    s->rootfd = open_root(env);
    if (s->rootfd < 0)
        return GAUDIT_CONF_UNSAFE;
    int missing;
    s->regfd = open_dir(env, s->rootfd, env->register_dir, create, &missing);
    if (s->regfd < 0) {
        if (!missing)
            return GAUDIT_CONF_UNSAFE;
        s->r.n = 0;
        return GAUDIT_CONF_NOT_THERE;  /* nothing written yet, nothing to lock */
    }
    s->lockfd = open_beneath(s->regfd, LOCK_FILE, O_RDWR | O_CREAT, 0600);
    if (s->lockfd < 0 || flock(s->lockfd, LOCK_EX) != 0)
        return GAUDIT_CONF_ERROR;
    if (load_register(env, s->regfd, &s->r) != 0)
        return GAUDIT_CONF_ERROR;  /* damaged: trust nothing */
    return GAUDIT_CONF_WRITTEN;
}

/* --- Preconditions --------------------------------------------------------- */

static gaudit_conf_result check_expect(const gaudit_conf_env *env, int rootfd,
                                       const gaudit_conf_expect *x)
{
    if (!valid_path(x->path) || (x->kind == GAUDIT_EXPECT_DIGEST && !valid_hex(x->sha256)))
        return GAUDIT_CONF_ERROR;
    char dir[MAX_PATH], name[MAX_PATH], hex[65];
    split(x->path, dir, name);
    int missing;
    int fd = open_dir(env, rootfd, dir, 0, &missing);
    if (fd < 0)
        return missing && x->kind == GAUDIT_EXPECT_ABSENT ? GAUDIT_CONF_WRITTEN
             : missing ? GAUDIT_CONF_PRECONDITION : GAUDIT_CONF_UNSAFE;
    if (x->kind == GAUDIT_EXPECT_PRESENT) {
        /* Only that it is there: a program may be larger than any
         * configuration file. */
        int f = open_beneath(fd, name, O_PATH, 0);
        struct stat st;
        int ok = f >= 0 && fstat(f, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == env->owner;
        if (f >= 0)
            close(f);
        close(fd);
        return ok ? GAUDIT_CONF_WRITTEN : GAUDIT_CONF_PRECONDITION;
    }
    int got = file_digest(env, fd, name, hex);
    close(fd);
    if (x->kind == GAUDIT_EXPECT_ABSENT)
        return got == 0 ? GAUDIT_CONF_WRITTEN : GAUDIT_CONF_PRECONDITION;
    return got == 1 && strcmp(hex, x->sha256) == 0 ? GAUDIT_CONF_WRITTEN : GAUDIT_CONF_PRECONDITION;
}

/* --- Writing and removing -------------------------------------------------- */

gaudit_conf_result gaudit_conf_write(const gaudit_conf_env *env, const gaudit_conf_plan *plan)
{
    if (plan == NULL || !valid_path(plan->path) || !valid_word(plan->template_id)
        || !valid_word(plan->values) || plan->content == NULL || plan->len > GAUDIT_CONF_MAX_FILE
        || (plan->mode & ~(mode_t)0644) != 0 || (plan->n_expect > 0 && plan->expect == NULL))
        return GAUDIT_CONF_ERROR;

    session s;
    gaudit_conf_result res = session_begin(env, 1, &s);
    if (res != GAUDIT_CONF_WRITTEN) {
        session_end(&s);
        return res == GAUDIT_CONF_NOT_THERE ? GAUDIT_CONF_ERROR : res;
    }

    for (size_t i = 0; i < plan->n_expect && res == GAUDIT_CONF_WRITTEN; i++)
        res = check_expect(env, s.rootfd, &plan->expect[i]);
    if (res != GAUDIT_CONF_WRITTEN) {
        session_end(&s);
        return res;
    }

    char dir[MAX_PATH], name[MAX_PATH], tmp[MAX_PATH + 16], now[65], want[65];
    split(plan->path, dir, name);
    snprintf(tmp, sizeof tmp, ".gaudit-new.%s", name);
    gaudit_sha256_hex(plan->content, plan->len, want);
    int missing;
    int dirfd = open_dir(env, s.rootfd, dir, 0, &missing);
    if (dirfd < 0) {
        session_end(&s);
        return GAUDIT_CONF_UNSAFE;
    }

    entry *e = find(&s.r, plan->path);
    int exists = file_digest(env, dirfd, name, now);
    if (exists < 0)
        res = GAUDIT_CONF_FOREIGN;  /* a link, another owner, ...: not ours to touch */
    else if (exists == 1 && e == NULL)
        res = GAUDIT_CONF_FOREIGN;
    else if (exists == 1 && strcmp(e->hex, now) != 0)
        res = GAUDIT_CONF_EDITED;
    else if (exists == 1 && strcmp(now, want) == 0)
        res = GAUDIT_CONF_UNCHANGED;

    if (res == GAUDIT_CONF_WRITTEN) {
        char again[65];
        if (write_new(dirfd, tmp, plan->content, plan->len, plan->mode) != 0) {
            res = GAUDIT_CONF_ERROR;
        } else if (file_digest(env, dirfd, name, again) != exists
                   || (exists == 1 && strcmp(again, now) != 0)) {
            unlinkat(dirfd, tmp, 0);  /* changed meanwhile: stop */
            res = GAUDIT_CONF_PRECONDITION;
        } else if (renameat2(dirfd, tmp, dirfd, name, exists ? 0 : RENAME_NOREPLACE) != 0) {
            unlinkat(dirfd, tmp, 0);
            res = errno == EEXIST ? GAUDIT_CONF_FOREIGN : GAUDIT_CONF_ERROR;
        } else if (fsync(dirfd) != 0) {
            res = GAUDIT_CONF_ERROR;
        }
    }
    close(dirfd);

    if (res == GAUDIT_CONF_WRITTEN || res == GAUDIT_CONF_UNCHANGED) {
        if (e == NULL) {
            if (s.r.n >= GAUDIT_CONF_MAX_ENTRIES) {
                session_end(&s);
                return GAUDIT_CONF_ERROR;
            }
            e = &s.r.e[s.r.n++];
        }
        snprintf(e->hex, sizeof e->hex, "%s", want);
        snprintf(e->template_id, sizeof e->template_id, "%s", plan->template_id);
        snprintf(e->values, sizeof e->values, "%s", plan->values);
        snprintf(e->path, sizeof e->path, "%s", plan->path);
        if (save_register(s.regfd, &s.r) != 0)
            res = GAUDIT_CONF_ERROR;
    }
    session_end(&s);
    return res;
}

gaudit_conf_result gaudit_conf_remove(const gaudit_conf_env *env, const char *path)
{
    if (!valid_path(path))
        return GAUDIT_CONF_ERROR;
    session s;
    gaudit_conf_result res = session_begin(env, 0, &s);
    if (res != GAUDIT_CONF_WRITTEN) {
        session_end(&s);
        return res;
    }
    char dir[MAX_PATH], name[MAX_PATH], now[65];
    split(path, dir, name);
    int missing;
    int dirfd = open_dir(env, s.rootfd, dir, 0, &missing);
    if (dirfd < 0) {
        session_end(&s);
        return missing ? GAUDIT_CONF_NOT_THERE : GAUDIT_CONF_UNSAFE;
    }
    entry *e = find(&s.r, path);
    int exists = file_digest(env, dirfd, name, now);
    if (e == NULL)
        res = exists == 0 ? GAUDIT_CONF_NOT_THERE : GAUDIT_CONF_FOREIGN;
    else if (exists < 0)
        res = GAUDIT_CONF_FOREIGN;
    else if (exists == 0)
        res = GAUDIT_CONF_NOT_THERE;  /* gone already: the entry goes too */
    else if (strcmp(e->hex, now) != 0)
        res = GAUDIT_CONF_EDITED;
    else if (unlinkat(dirfd, name, 0) != 0 || fsync(dirfd) != 0)
        res = GAUDIT_CONF_ERROR;
    else
        res = GAUDIT_CONF_REMOVED;
    close(dirfd);
    if (e != NULL && (res == GAUDIT_CONF_REMOVED || res == GAUDIT_CONF_NOT_THERE)) {
        drop(&s.r, e);
        if (save_register(s.regfd, &s.r) != 0)
            res = GAUDIT_CONF_ERROR;
    }
    session_end(&s);
    return res;
}

int gaudit_conf_owned(const gaudit_conf_env *env, const char *path, char *template_id,
                      char *values)
{
    if (!valid_path(path))
        return -1;
    session s;
    gaudit_conf_result res = session_begin(env, 0, &s);
    if (res == GAUDIT_CONF_NOT_THERE) {
        session_end(&s);
        return 0;
    }
    if (res != GAUDIT_CONF_WRITTEN) {
        session_end(&s);
        return -1;
    }
    char dir[MAX_PATH], name[MAX_PATH], now[65];
    split(path, dir, name);
    int missing, owned = 0;
    int dirfd = open_dir(env, s.rootfd, dir, 0, &missing);
    entry *e = find(&s.r, path);
    if (dirfd < 0) {
        owned = missing ? 0 : -1;
    } else {
        int exists = file_digest(env, dirfd, name, now);
        owned = exists < 0 ? -1 : exists == 1 && e != NULL && strcmp(e->hex, now) == 0;
        close(dirfd);
    }
    if (owned == 1) {
        if (template_id != NULL)
            snprintf(template_id, MAX_WORD, "%s", e->template_id);
        if (values != NULL)
            snprintf(values, MAX_WORD, "%s", e->values);
    }
    session_end(&s);
    return owned;
}
