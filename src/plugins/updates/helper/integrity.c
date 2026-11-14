/* SPDX-License-Identifier: GPL-3.0-only */
#include "integrity.h"

#include "md5.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_LINE   (PATH_MAX + 64)
#define READ_CHUNK (64 * 1024)
#define MAX_THREADS 32

/* --- dpkg's path filters ------------------------------------------------- */

typedef struct {
    int include;
    char *pattern;
} filter;

typedef struct {
    filter *items;
    size_t n, cap;
} filter_list;

static int filters_add(filter_list *f, int include, const char *pattern)
{
    if (f->n == f->cap) {
        size_t cap = f->cap ? f->cap * 2 : 8;
        filter *items = realloc(f->items, cap * sizeof *items);
        if (items == NULL)
            return -1;
        f->items = items;
        f->cap = cap;
    }
    f->items[f->n].pattern = strdup(pattern);
    if (f->items[f->n].pattern == NULL)
        return -1;
    f->items[f->n++].include = include;
    return 0;
}

/* "path-exclude=GLOB" or "path-include=GLOB" lines (also with a leading
 * "--", or a space instead of "="); everything else is ignored. */
static int filters_read(filter_list *f, const char *file)
{
    FILE *fp = fopen(file, "re");
    if (fp == NULL)
        return 0;
    char line[MAX_LINE];
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        const char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (p[0] == '-' && p[1] == '-')
            p += 2;
        int include;
        if (strncmp(p, "path-exclude", 12) == 0)
            include = 0;
        else if (strncmp(p, "path-include", 12) == 0)
            include = 1;
        else
            continue;
        p += 12;
        if (*p != '=' && *p != ' ' && *p != '\t')
            continue;
        while (*p == '=' || *p == ' ' || *p == '\t')
            p++;
        if (*p != '\0')
            rc = filters_add(f, include, p);
    }
    fclose(fp);
    return rc;
}

static int name_sort(const struct dirent **a, const struct dirent **b)
{
    return strcmp((*a)->d_name, (*b)->d_name);
}

/* dpkg's fragment names: [0-9a-zA-Z_-]* */
static int fragment_name(const struct dirent *d)
{
    if (d->d_name[0] == '\0')
        return 0;
    for (const char *c = d->d_name; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z')
              || *c == '_' || *c == '-'))
            return 0;
    return 1;
}

/* As dpkg reads them: the fragments in name order, then the main file. */
static int filters_load(filter_list *f, const char *cfg_dir, const char *cfg_file)
{
    if (cfg_dir != NULL) {
        struct dirent **names;
        int n = scandir(cfg_dir, &names, fragment_name, name_sort);
        for (int i = 0; i < n; i++) {
            char path[PATH_MAX];
            int len = snprintf(path, sizeof path, "%s/%s", cfg_dir, names[i]->d_name);
            if (len > 0 && (size_t)len < sizeof path && filters_read(f, path) != 0) {
                for (int j = i; j < n; j++)
                    free(names[j]);
                free(names);
                return -1;
            }
            free(names[i]);
        }
        if (n >= 0)
            free(names);
    }
    return cfg_file != NULL ? filters_read(f, cfg_file) : 0;
}

/* The last filter that matches decides, as in dpkg. */
static int excluded(const filter_list *f, const char *path)
{
    int out = 0;
    for (size_t i = 0; i < f->n; i++)
        if (fnmatch(f->items[i].pattern, path, 0) == 0)
            out = !f->items[i].include;
    return out;
}

static void filters_free(filter_list *f)
{
    for (size_t i = 0; i < f->n; i++)
        free(f->items[i].pattern);
    free(f->items);
}

/* --- Diversions ----------------------------------------------------------- */

typedef struct {
    char **paths;  /* the diverted ("from") paths, sorted */
    size_t n;
} diversion_list;

static int str_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Groups of three lines: from, to, package. */
static int diversions_load(diversion_list *d, const char *file)
{
    FILE *fp = file != NULL ? fopen(file, "re") : NULL;
    if (fp == NULL)
        return 0;
    char line[MAX_LINE];
    size_t cap = 0;
    int rc = 0;
    for (unsigned long i = 0; rc == 0 && fgets(line, sizeof line, fp) != NULL; i++) {
        if (i % 3 != 0)
            continue;
        line[strcspn(line, "\n")] = '\0';
        if (d->n == cap) {
            cap = cap ? cap * 2 : 32;
            char **paths = realloc(d->paths, cap * sizeof *paths);
            if (paths == NULL) {
                rc = -1;
                break;
            }
            d->paths = paths;
        }
        if ((d->paths[d->n] = strdup(line)) == NULL)
            rc = -1;
        else
            d->n++;
    }
    fclose(fp);
    if (d->n > 0)
        qsort(d->paths, d->n, sizeof *d->paths, str_cmp);
    return rc;
}

static int diverted(const diversion_list *d, const char *path)
{
    return d->n > 0 && bsearch(&path, d->paths, d->n, sizeof *d->paths, str_cmp) != NULL;
}

static void diversions_free(diversion_list *d)
{
    for (size_t i = 0; i < d->n; i++)
        free(d->paths[i]);
    free(d->paths);
}

/* --- The scan ------------------------------------------------------------- */

typedef struct {
    const gaudit_integrity_paths *paths;
    filter_list filters;
    diversion_list diversions;
    struct dirent **lists;
    int n_lists;
    unsigned next;               /* next list to take (atomic) */
    pthread_mutex_t lock;        /* guards out and fn */
    gaudit_integrity_result *out;
    gaudit_integrity_fn fn;
    void *ctx;
} scan_state;

static int md5sums_name(const struct dirent *d)
{
    size_t n = strlen(d->d_name);
    return n > 8 && strcmp(d->d_name + n - 8, ".md5sums") == 0;
}

static int is_hex32(const char *s)
{
    for (int i = 0; i < 32; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

/* A relative path without "." or ".." components. */
static int safe_path(const char *p)
{
    if (*p == '\0' || *p == '/')
        return 0;
    for (const char *c = p; *c != '\0';) {
        const char *end = strchr(c, '/');
        size_t len = end != NULL ? (size_t)(end - c) : strlen(c);
        if (len == 0 || (len == 1 && c[0] == '.') || (len == 2 && c[0] == '.' && c[1] == '.'))
            return 0;
        c += len + (end != NULL);
    }
    return 1;
}

static void report(scan_state *st, gaudit_integrity_kind kind, const char *package, const char *path)
{
    pthread_mutex_lock(&st->lock);
    if (st->fn != NULL)
        st->fn(kind, package, path, st->ctx);
    pthread_mutex_unlock(&st->lock);
}

/* 0 equal, 1 changed, 2 missing, 3 unreadable. */
static int check_file(const char *full, const char *want, unsigned char *buf,
                      unsigned long long *bytes)
{
    int fd = open(full, O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT || errno == ENOTDIR ? 2
             : errno == ELOOP ? 1  /* replaced by a symbolic link */
             : 3;
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        close(fd);
        return 3;
    }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        return 1;
    }
    /* Read once, start to end; afterwards drop it from the page cache, so
     * tens of gigabytes of package files do not push out what the rest
     * of the system is using. */
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    gaudit_md5 md5;
    gaudit_md5_init(&md5);
    for (;;) {
        ssize_t n = read(fd, buf, READ_CHUNK);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return 3;
        }
        if (n == 0)
            break;
        gaudit_md5_update(&md5, buf, (size_t)n);
        *bytes += (unsigned long long)n;
    }
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    unsigned char digest[16];
    char hex[33];
    gaudit_md5_final(&md5, digest);
    gaudit_md5_hex(digest, hex);
    return memcmp(hex, want, 32) == 0 ? 0 : 1;
}

static void scan_list(scan_state *st, const char *list_name, unsigned char *buf,
                      gaudit_integrity_result *mine)
{
    char package[NAME_MAX + 1];
    size_t plen = strlen(list_name) - 8;  /* without ".md5sums" */
    memcpy(package, list_name, plen);
    package[plen] = '\0';

    char list_path[PATH_MAX];
    int n = snprintf(list_path, sizeof list_path, "%s/%s", st->paths->info_dir, list_name);
    FILE *fp = n > 0 && (size_t)n < sizeof list_path ? fopen(list_path, "re") : NULL;
    if (fp == NULL) {
        mine->bad_lines++;
        return;
    }
    mine->packages++;
    char line[MAX_LINE];
    while (fgets(line, sizeof line, fp) != NULL) {
        size_t len = strcspn(line, "\n");
        if (line[len] != '\n' && !feof(fp)) {
            /* Longer than any path: skip the rest of it. */
            mine->bad_lines++;
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n')
                ;
            continue;
        }
        line[len] = '\0';
        if (len == 0)
            continue;
        const char *rel = line + 34;
        if (len < 35 || !is_hex32(line) || line[32] != ' ' || line[33] != ' ' || !safe_path(rel)) {
            mine->bad_lines++;
            continue;
        }
        mine->files++;
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "/%s", rel) >= (int)sizeof path) {
            mine->bad_lines++;
            continue;
        }
        if (diverted(&st->diversions, path)) {
            mine->diverted++;
            continue;
        }
        char full[PATH_MAX];
        if (snprintf(full, sizeof full, "%s%s", st->paths->root, path) >= (int)sizeof full) {
            mine->bad_lines++;
            continue;
        }
        switch (check_file(full, line, buf, &mine->bytes)) {
        case 0:
            mine->checked++;
            break;
        case 1:
            mine->checked++;
            mine->changed++;
            report(st, GAUDIT_INTEGRITY_CHANGED, package, path);
            break;
        case 2:
            if (excluded(&st->filters, path)) {
                mine->excluded++;
            } else {
                mine->missing++;
                report(st, GAUDIT_INTEGRITY_MISSING, package, path);
            }
            break;
        default:
            mine->unreadable++;
            report(st, GAUDIT_INTEGRITY_UNREADABLE, package, path);
            break;
        }
    }
    fclose(fp);
}

static void *worker(void *arg)
{
    scan_state *st = arg;
    unsigned char *buf = malloc(READ_CHUNK);
    gaudit_integrity_result mine;
    memset(&mine, 0, sizeof mine);
    if (buf != NULL) {
        for (;;) {
            unsigned i = __atomic_fetch_add(&st->next, 1, __ATOMIC_RELAXED);
            if (i >= (unsigned)st->n_lists)
                break;
            scan_list(st, st->lists[i]->d_name, buf, &mine);
        }
    }
    free(buf);
    pthread_mutex_lock(&st->lock);
    gaudit_integrity_result *o = st->out;
    o->packages += mine.packages;
    o->files += mine.files;
    o->checked += mine.checked;
    o->changed += mine.changed;
    o->missing += mine.missing;
    o->unreadable += mine.unreadable;
    o->excluded += mine.excluded;
    o->diverted += mine.diverted;
    o->bad_lines += mine.bad_lines;
    o->bytes += mine.bytes;
    pthread_mutex_unlock(&st->lock);
    return buf != NULL ? NULL : (void *)1;
}

int gaudit_integrity_scan(const gaudit_integrity_paths *paths, gaudit_integrity_result *out,
                          gaudit_integrity_fn fn, void *ctx)
{
    if (paths == NULL || paths->root == NULL || paths->info_dir == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof *out);

    scan_state st;
    memset(&st, 0, sizeof st);
    st.paths = paths;
    st.out = out;
    st.fn = fn;
    st.ctx = ctx;
    pthread_mutex_init(&st.lock, NULL);

    int rc = -1;
    if (filters_load(&st.filters, paths->cfg_dir, paths->cfg_file) != 0
        || diversions_load(&st.diversions, paths->diversions) != 0)
        goto done;
    st.n_lists = scandir(paths->info_dir, &st.lists, md5sums_name, name_sort);
    if (st.n_lists < 0)
        goto done;

    unsigned n_threads = paths->threads < 1 ? 1 : paths->threads > MAX_THREADS ? MAX_THREADS
                       : paths->threads;
    pthread_t threads[MAX_THREADS];
    unsigned started = 0;
    for (; started < n_threads; started++)
        if (pthread_create(&threads[started], NULL, worker, &st) != 0)
            break;
    int failed = started == 0;
    for (unsigned i = 0; i < started; i++) {
        void *res;
        pthread_join(threads[i], &res);
        failed |= res != NULL;
    }
    rc = failed ? -1 : 0;

    for (int i = 0; i < st.n_lists; i++)
        free(st.lists[i]);
    free(st.lists);
done:
    filters_free(&st.filters);
    diversions_free(&st.diversions);
    pthread_mutex_destroy(&st.lock);
    return rc;
}
