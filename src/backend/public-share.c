/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "public-share.h"

#include "xdg-public-names.h"

#include <dirent.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE   (1 << 20)   /* a catalog or a settings file */
#define MAX_NAMES  512

/* --- Reading files ----------------------------------------------------------- */

static unsigned char *read_file(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE) {
        close(fd);
        return NULL;
    }
    unsigned char *buf = malloc((size_t)st.st_size + 1);
    size_t got = 0;
    while (buf != NULL && got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (buf != NULL) {
        buf[got] = '\0';
        *len = got;
    }
    return buf;
}

/* --- A .mo catalog ------------------------------------------------------------ */

static int u32_at(const unsigned char *d, size_t len, uint64_t off, int big, uint32_t *v)
{
    if (off + 4 > len)
        return -1;
    const unsigned char *p = d + off;
    *v = big ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]
             : (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
    return 0;
}

/* String i of the table at off: its bytes, NUL-terminated within the data. */
static const char *mo_string(const unsigned char *d, size_t len, uint32_t table, uint32_t i,
                             int big, uint32_t *slen)
{
    uint32_t l, o;
    if (u32_at(d, len, (uint64_t)table + 8ULL * i, big, &l) != 0
        || u32_at(d, len, (uint64_t)table + 8ULL * i + 4, big, &o) != 0
        || (uint64_t)o + l >= len || d[(size_t)o + l] != '\0')
        return NULL;
    *slen = l;
    return (const char *)d + o;
}

int gaudit_mo_lookup(const unsigned char *d, size_t len, const char *msgid, char *out,
                     size_t out_len)
{
    if (d == NULL || msgid == NULL || out == NULL || out_len == 0 || len < 28)
        return -1;
    uint32_t magic, rev, n, orig, trans;
    if (u32_at(d, len, 0, 0, &magic) != 0)
        return -1;
    int big;
    if (magic == 0x950412deU)
        big = 0;
    else if (magic == 0xde120495U)
        big = 1;
    else
        return -1;
    if (u32_at(d, len, 4, big, &rev) != 0 || (rev >> 16) > 1 || u32_at(d, len, 8, big, &n) != 0
        || u32_at(d, len, 12, big, &orig) != 0 || u32_at(d, len, 16, big, &trans) != 0
        || n > 100000)
        return -1;
    size_t want = strlen(msgid);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t ol, tl;
        const char *o = mo_string(d, len, orig, i, big, &ol);
        if (o == NULL)
            return -1;  /* not well formed: trust none of it */
        if (ol != want || memcmp(o, msgid, want) != 0)
            continue;
        const char *t = mo_string(d, len, trans, i, big, &tl);
        if (t == NULL)
            return -1;
        size_t first = strnlen(t, tl);  /* the first form of a plural */
        if (first == 0 || first >= out_len)
            return -1;
        memcpy(out, t, first);
        out[first] = '\0';
        return 0;
    }
    return -1;
}

/* --- user-dirs.dirs ------------------------------------------------------------ */

gaudit_public_config gaudit_public_parse_user_dirs(const char *text, const char *home, char *out,
                                                   size_t out_len)
{
    static const char key[] = "XDG_PUBLICSHARE_DIR=";
    gaudit_public_config result = GAUDIT_PUBLIC_CONFIG_NONE;
    out[0] = '\0';
    for (const char *line = text; line != NULL && *line != '\0';) {
        const char *end = strchr(line, '\n');
        size_t ll = end != NULL ? (size_t)(end - line) : strlen(line);
        const char *p = line;
        while (p < line + ll && (*p == ' ' || *p == '\t'))
            p++;
        if (p < line + ll && *p != '#' && strncmp(p, key, sizeof key - 1) == 0) {
            /* The last definition counts, as in a shell. */
            p += sizeof key - 1;
            char value[512];
            size_t v = 0;
            int ok = p < line + ll && *p == '"', closed = 0, dollar_home = 0;
            if (ok)
                p++;
            if (ok && strncmp(p, "$HOME", 5) == 0 && (p[5] == '/' || p[5] == '"')) {
                dollar_home = 1;
                p += 5;
            }
            while (ok && p < line + ll) {
                char c = *p++;
                if (c == '"') {
                    closed = 1;
                    break;
                }
                if (c == '\\' && p < line + ll)
                    c = *p++;
                else if (c == '$' || c == '`')
                    ok = 0;  /* another variable or a command: not what xdg-user-dirs writes */
                if (v + 1 >= sizeof value)
                    ok = 0;
                else
                    value[v++] = c;
            }
            value[v] = '\0';
            /* Nothing but blanks or a comment after the closing quote. */
            while (closed && p < line + ll && (*p == ' ' || *p == '\t'))
                p++;
            if (!ok || !closed || (p < line + ll && *p != '#')
                || (!dollar_home && value[0] != '/')) {
                result = GAUDIT_PUBLIC_CONFIG_UNKNOWN;
                out[0] = '\0';
            } else {
                char full[1024];
                snprintf(full, sizeof full, "%s%s", dollar_home ? home : "", value);
                size_t fl = strlen(full);
                while (fl > 1 && full[fl - 1] == '/')
                    full[--fl] = '\0';
                char h[512];
                snprintf(h, sizeof h, "%s", home);
                size_t hl = strlen(h);
                while (hl > 1 && h[hl - 1] == '/')
                    h[--hl] = '\0';
                if (strcmp(full, h) == 0) {
                    result = GAUDIT_PUBLIC_CONFIG_DISABLED;
                    out[0] = '\0';
                } else if (fl < out_len && strstr(full, "/../") == NULL
                           && (fl < 3 || strcmp(full + fl - 3, "/..") != 0)) {
                    result = GAUDIT_PUBLIC_CONFIG_SET;
                    memcpy(out, full, fl + 1);
                } else {
                    result = GAUDIT_PUBLIC_CONFIG_UNKNOWN;
                    out[0] = '\0';
                }
            }
        }
        line = end != NULL ? end + 1 : NULL;
    }
    return result;
}

/* --- The names ---------------------------------------------------------------- */

typedef struct {
    char name[256];
    char lang[32];
    int from_machine, current;
} name_entry;

typedef struct {
    name_entry *e;
    unsigned n;
} names;

/* A name a folder can have: one path component, no control characters. */
static int plain_name(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= 256 || strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
        return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++)
        if (*p < 0x20 || *p == 0x7f || *p == '/')
            return 0;
    return 1;
}

static void add_name(names *ns, const char *name, const char *lang, int from_machine, int current)
{
    if (!plain_name(name))
        return;
    for (unsigned i = 0; i < ns->n; i++)
        if (strcmp(ns->e[i].name, name) == 0 && strcmp(ns->e[i].lang, lang) == 0) {
            ns->e[i].from_machine |= from_machine;
            ns->e[i].current |= current;
            return;
        }
    if (ns->n >= MAX_NAMES)
        return;
    name_entry *e = &ns->e[ns->n++];
    snprintf(e->name, sizeof e->name, "%s", name);
    snprintf(e->lang, sizeof e->lang, "%s", lang);
    e->from_machine = from_machine;
    e->current = current;
}

/* A language folder's name: letters, digits, '_', '@', '.', '-'. */
static int plain_lang(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= 32 || s[0] == '.')
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9')
              || *c == '_' || *c == '@' || *c == '.' || *c == '-'))
            return 0;
    return 1;
}

static void add_machine_names(names *ns, const char *dir)
{
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!plain_lang(de->d_name))
            continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s/LC_MESSAGES/xdg-user-dirs.mo", dir, de->d_name);
        size_t len = 0;
        unsigned char *mo = read_file(path, &len);
        char name[256];
        if (mo != NULL && gaudit_mo_lookup(mo, len, "Public", name, sizeof name) == 0)
            add_name(ns, name, de->d_name, 1, 1);
        free(mo);
    }
    closedir(d);
}

/* --- The search --------------------------------------------------------------- */

static void first_line(const char *path, char *out, size_t len)
{
    size_t got = 0;
    unsigned char *text = read_file(path, &got);
    out[0] = '\0';
    if (text != NULL) {
        snprintf(out, len, "%.*s", (int)strcspn((char *)text, "\r\n"), (char *)text);
        for (char *c = out; *c != '\0'; c++)
            if ((unsigned char)*c < 0x20 || *c == 0x7f)
                *c = '?';
    }
    free(text);
}

static void system_default(const char *path, char *out, size_t len)
{
    size_t got = 0;
    char *text = (char *)read_file(path, &got);
    out[0] = '\0';
    for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        while (*line == ' ' || *line == '\t')
            line++;
        if (strncmp(line, "PUBLICSHARE=", 12) == 0) {
            char *v = line + 12;
            v[strcspn(v, " \t#")] = '\0';
            if (plain_name(v))
                snprintf(out, len, "%s", v);
            else
                out[0] = '\0';
        }
    }
    free(text);
}

/* What a folder holds, counted up to 1000, never through a link; -1 when
 * it cannot be read. */
static long count_entries(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
    if (d == NULL) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    long n = 0;
    struct dirent *de;
    while (n < 1000 && (de = readdir(d)) != NULL)
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            n++;
    closedir(d);
    return n;
}

/* The language of user-dirs.locale as a catalog's would start ("nb_NO" -> "nb"). */
static int lang_matches(const char *catalog_lang, const char *locale)
{
    size_t n = strcspn(locale, "_.@");
    return n > 0 && strncmp(catalog_lang, locale, n) == 0
           && (catalog_lang[n] == '\0' || catalog_lang[n] == '_' || catalog_lang[n] == '@');
}

int gaudit_public_share_find(const gaudit_public_where *where, gaudit_public_share *out)
{
    memset(out, 0, sizeof *out);
    if (where == NULL || where->home == NULL || where->home[0] != '/')
        return -1;
    const char *home = where->home;
    char user_dirs[1024], user_locale[1024];
    snprintf(user_dirs, sizeof user_dirs, "%s/.config/user-dirs.dirs", home);
    snprintf(user_locale, sizeof user_locale, "%s/.config/user-dirs.locale", home);

    size_t len = 0;
    char *dirs_text = (char *)read_file(where->user_dirs != NULL ? where->user_dirs : user_dirs, &len);
    if (dirs_text != NULL)
        out->config = gaudit_public_parse_user_dirs(dirs_text, home, out->standard,
                                                    sizeof out->standard);
    free(dirs_text);
    struct stat st;
    out->standard_exists = out->config == GAUDIT_PUBLIC_CONFIG_SET && stat(out->standard, &st) == 0
                           && S_ISDIR(st.st_mode);
    first_line(where->user_locale != NULL ? where->user_locale : user_locale, out->locale,
               sizeof out->locale);
    system_default(where->system_defaults != NULL ? where->system_defaults
                                                  : "/etc/xdg/user-dirs.defaults",
                   out->system_default, sizeof out->system_default);

    /* Every name it can have: the project's table, the machine's catalogs,
     * the system's default and the one user-dirs.dirs names. */
    names ns = { calloc(MAX_NAMES, sizeof(name_entry)), 0 };
    if (ns.e == NULL)
        return -1;
    for (unsigned i = 0; i < gaudit_xdg_public_names_count; i++)
        add_name(&ns, gaudit_xdg_public_names[i].name, gaudit_xdg_public_names[i].lang, 0,
                 gaudit_xdg_public_names[i].current);
    static const char *const usual[] = { "/usr/share/locale", "/usr/share/locale-langpack", NULL };
    const char *const *dirs = where->locale_dirs != NULL ? where->locale_dirs : usual;
    for (size_t i = 0; dirs[i] != NULL; i++)
        add_machine_names(&ns, dirs[i]);
    if (out->system_default[0] != '\0')
        add_name(&ns, out->system_default, "", 1, 1);
    const char *standard_base = NULL;
    if (out->config == GAUDIT_PUBLIC_CONFIG_SET) {
        size_t hl = strlen(home);
        const char *rest = out->standard + hl;
        if (strncmp(out->standard, home, hl) == 0 && rest[0] == '/' && strchr(rest + 1, '/') == NULL)
            standard_base = rest + 1;  /* straight in the home folder */
        if (standard_base != NULL)
            add_name(&ns, standard_base, "", 1, 1);
    }
    out->names = ns.n;

    /* The home folder's own folders (and links) with one of those names. */
    struct stat home_st;
    dev_t home_dev = stat(home, &home_st) == 0 ? home_st.st_dev : 0;
    DIR *d = opendir(home);
    if (d == NULL) {
        free(ns.e);
        return -1;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", home, de->d_name);
        if (lstat(path, &st) != 0 || !(S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)))
            continue;
        const name_entry *best = NULL;
        int best_score = -1, case_differs = 0;
        for (unsigned i = 0; i < ns.n; i++) {
            int exact = strcmp(ns.e[i].name, de->d_name) == 0;
            if (!exact && strcasecmp(ns.e[i].name, de->d_name) != 0)
                continue;
            /* Prefer exact, then the language the names were made in, then
             * what the machine itself says. */
            int score = exact * 4 + (out->locale[0] != '\0' && lang_matches(ns.e[i].lang, out->locale)) * 2
                        + ns.e[i].from_machine;
            if (score > best_score) {
                best = &ns.e[i];
                best_score = score;
                case_differs = !exact;
            }
        }
        if (best == NULL)
            continue;
        if (out->n_found >= GAUDIT_PUBLIC_MAX_FOUND) {
            out->more = 1;
            continue;
        }
        gaudit_public_folder *f = &out->found[out->n_found++];
        snprintf(f->name, sizeof f->name, "%s", de->d_name);
        snprintf(f->lang, sizeof f->lang, "%s", best->lang);
        f->from_machine = best->from_machine;
        f->current_name = best->current;
        f->case_differs = case_differs;
        f->is_standard = standard_base != NULL && strcmp(standard_base, de->d_name) == 0;
        if (S_ISLNK(st.st_mode)) {
            f->symlink = 1;
            ssize_t n = readlink(path, f->link_target, sizeof f->link_target - 1);
            f->link_target[n > 0 ? n : 0] = '\0';
        } else if (st.st_dev != home_dev) {
            /* A mount (a network or cloud folder, another disk): never
             * listed, since listing it may fetch it over the network. */
            f->entries = -2;
        } else {
            f->entries = count_entries(path);
        }
    }
    closedir(d);
    free(ns.e);
    return 0;
}

/* --- Tidying up the structure ------------------------------------------------- */

/* A folder straight beneath dirfd by one plain name, never through a link,
 * the user's own; -1 otherwise. */
static int open_own_folder(int dirfd, const char *name)
{
    if (name == NULL || !plain_name(name))
        return -1;
    struct open_how how = {
        .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    int fd = (int)syscall(SYS_openat2, dirfd, name, &how, sizeof how);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid())) {
        close(fd);
        fd = -1;
    }
    return fd;
}

/* Both folders opened, checked, and the duplicate's listing; -1 refused. */
static int merge_open(const char *home, const char *from, const char *to, int *from_fd, int *to_fd,
                      DIR **d)
{
    *from_fd = *to_fd = -1;
    *d = NULL;
    if (home == NULL || home[0] != '/' || from == NULL || to == NULL || strcmp(from, to) == 0)
        return -1;
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
        return -1;
    *from_fd = open_own_folder(home_fd, from);
    *to_fd = open_own_folder(home_fd, to);
    close(home_fd);
    struct stat a, b;
    int list_fd = *from_fd >= 0 ? dup(*from_fd) : -1;
    *d = list_fd >= 0 ? fdopendir(list_fd) : NULL;
    if (*d == NULL && list_fd >= 0)
        close(list_fd);
    struct stat h;
    /* Both on the home folder's own filesystem: a mount is never listed
     * (that may fetch it over the network) nor moved across. */
    if (*from_fd < 0 || *to_fd < 0 || *d == NULL || fstat(*from_fd, &a) != 0
        || fstat(*to_fd, &b) != 0 || (a.st_dev == b.st_dev && a.st_ino == b.st_ino)
        || stat(home, &h) != 0 || a.st_dev != h.st_dev || b.st_dev != h.st_dev) {
        if (*d != NULL)
            closedir(*d);
        if (*from_fd >= 0)
            close(*from_fd);
        if (*to_fd >= 0)
            close(*to_fd);
        return -1;
    }
    return 0;
}

static void note_clash(gaudit_public_merge_result *r, const char *name)
{
    if (r->clashes < GAUDIT_PUBLIC_MAX_CLASHES)
        snprintf(r->clash[r->clashes], sizeof r->clash[0], "%s", name);
    r->clashes++;
}

/* The check, on open folders: each entry by itself, never through a link. */
static int merge_scan(int from_fd, int to_fd, DIR *d, gaudit_public_merge_result *r)
{
    struct stat to_st;
    if (fstat(to_fd, &to_st) != 0)
        return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(to_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
            note_clash(r, de->d_name);         /* a name already in use: the user decides */
        else if (errno != ENOENT)
            r->failed++;
        else if (fstatat(from_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            r->failed++;
        else if (st.st_dev != to_st.st_dev)
            r->other_disk++;                   /* a mount inside: never copied */
        else
            r->moved++;                        /* can go */
    }
    rewinddir(d);
    return r->clashes + r->other_disk + r->failed == 0 ? 0 : 1;
}

int gaudit_public_merge_check(const char *home, const char *from, const char *to,
                              gaudit_public_merge_result *r)
{
    memset(r, 0, sizeof *r);
    int from_fd, to_fd;
    DIR *d;
    if (merge_open(home, from, to, &from_fd, &to_fd, &d) != 0)
        return -1;
    int result = merge_scan(from_fd, to_fd, d, r);
    closedir(d);
    close(from_fd);
    close(to_fd);
    return result;
}

int gaudit_public_merge(const char *home, const char *from, const char *to,
                        gaudit_public_merge_result *r)
{
    memset(r, 0, sizeof *r);
    int from_fd, to_fd;
    DIR *d;
    if (merge_open(home, from, to, &from_fd, &to_fd, &d) != 0)
        return -1;
    int result = merge_scan(from_fd, to_fd, d, r);
    if (result == 0) {
        /* Nothing in the way: move, still never replacing. */
        memset(r, 0, sizeof *r);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            if (renameat2(from_fd, de->d_name, to_fd, de->d_name, RENAME_NOREPLACE) == 0)
                r->moved++;
            else if (errno == EEXIST)
                note_clash(r, de->d_name);
            else if (errno == EXDEV)
                r->other_disk++;
            else
                r->failed++;
        }
        result = r->clashes + r->other_disk + r->failed == 0 ? 0 : 1;
    } else {
        r->moved = 0;  /* nothing was moved */
    }
    closedir(d);
    close(from_fd);
    close(to_fd);
    return result;
}

int gaudit_public_remove_empty(const char *home, const char *name)
{
    if (home == NULL || home[0] != '/')
        return -1;
    int home_fd = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (home_fd < 0)
        return -1;
    int fd = open_own_folder(home_fd, name);
    if (fd < 0) {
        close(home_fd);
        return -1;
    }
    close(fd);
    /* Fails by itself unless it is an empty folder, also if it was swapped
     * for a link meanwhile: a link is not a folder to remove. */
    int r = unlinkat(home_fd, name, AT_REMOVEDIR);
    int err = errno;
    close(home_fd);
    if (r == 0)
        return 0;
    return err == ENOTEMPTY || err == EEXIST ? 1 : -1;
}

/* --- Services that share folders ------------------------------------------- */

int gaudit_path_within(const char *path, const char *folder)
{
    size_t n = strlen(folder);
    return n > 0 && strncmp(path, folder, n) == 0 && (path[n] == '\0' || path[n] == '/'
                                                      || strcmp(folder, "/") == 0);
}

static void add_share(gaudit_share_services *out, gaudit_share_kind kind, const char *name,
                      const char *path)
{
    if (path == NULL || path[0] != '/')
        return;
    if (out->n >= GAUDIT_SHARE_MAX) {
        out->more = 1;
        return;
    }
    gaudit_share_service *s = &out->s[out->n++];
    s->kind = kind;
    snprintf(s->name, sizeof s->name, "%s", name);
    snprintf(s->path, sizeof s->path, "%s", path);
    size_t l = strlen(s->path);
    while (l > 1 && s->path[l - 1] == '/')
        s->path[--l] = '\0';
    for (char *c = s->name; *c != '\0'; c++)
        if ((unsigned char)*c < 0x20 || *c == 0x7f)
            *c = '?';
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        s[--n] = '\0';
    return s;
}

/* smb.conf: the shares' paths ([homes] is the home folder), and where the
 * usershares are kept. Parameter names are compared without case or
 * spaces, as Samba does. */
static void read_smb_conf(const char *path, const char *home, gaudit_share_services *out,
                          char *usershare_dir, size_t len)
{
    size_t got = 0;
    char *text = (char *)read_file(path, &got);
    char section[128] = "";
    for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        char *l = trim(line);
        if (*l == '#' || *l == ';' || *l == '\0')
            continue;
        if (*l == '[') {
            char *close = strchr(l, ']');
            if (close != NULL) {
                *close = '\0';
                snprintf(section, sizeof section, "%s", l + 1);
                if (strcasecmp(section, "homes") == 0)
                    add_share(out, GAUDIT_SHARE_SAMBA, "homes", home);
            }
            continue;
        }
        char *eq = strchr(l, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        char key[64];
        size_t k = 0;
        for (char *c = l; *c != '\0' && k + 1 < sizeof key; c++)
            if (*c != ' ' && *c != '\t')
                key[k++] = (char)(*c >= 'A' && *c <= 'Z' ? *c + 32 : *c);
        key[k] = '\0';
        char *value = trim(eq + 1);
        if (strcasecmp(section, "global") == 0 && strcmp(key, "usersharepath") == 0)
            snprintf(usershare_dir, len, "%s", value);
        else if (strcmp(key, "path") == 0 && strcasecmp(section, "global") != 0
                 && strcasecmp(section, "printers") != 0 && strcasecmp(section, "homes") != 0
                 && strstr(value, "%") == NULL)
            add_share(out, GAUDIT_SHARE_SAMBA, section, value);
    }
    free(text);
}

static void read_usershares(const char *dir, gaudit_share_services *out)
{
    DIR *d = opendir(dir);
    if (d == NULL) {
        struct stat st;
        if (errno == EACCES && stat(dir, &st) == 0)
            out->usershares_unreadable = 1;
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        size_t got = 0;
        char *text = (char *)read_file(path, &got);
        char shared[512] = "", name[128] = "";
        snprintf(name, sizeof name, "%.127s", de->d_name);
        for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
            next = strchr(line, '\n');
            if (next != NULL)
                *next++ = '\0';
            if (strncmp(line, "path=", 5) == 0)
                snprintf(shared, sizeof shared, "%s", trim(line + 5));
            else if (strncmp(line, "sharename=", 10) == 0)
                snprintf(name, sizeof name, "%s", trim(line + 10));
        }
        free(text);
        add_share(out, GAUDIT_SHARE_SAMBA_USER, name, shared);
    }
    closedir(d);
}

/* gnome-user-share's programs running as uid. */
static void read_gnome_user_share(const char *proc, unsigned uid, const char *publicshare,
                                  gaudit_share_services *out)
{
    DIR *d = opendir(proc);
    if (d == NULL)
        return;
    int seen = 0;
    struct dirent *de;
    while (!seen && (de = readdir(d)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;
        char path[512], target[512];
        snprintf(path, sizeof path, "%s/%s/status", proc, de->d_name);
        size_t got = 0;
        char *status = (char *)read_file(path, &got);
        const char *u = status != NULL ? strstr(status, "\nUid:") : NULL;
        unsigned real = 0;
        int mine = u != NULL && sscanf(u + 6, "%u", &real) == 1 && real == uid;
        free(status);
        if (!mine)
            continue;
        snprintf(path, sizeof path, "%s/%s/exe", proc, de->d_name);
        ssize_t n = readlink(path, target, sizeof target - 1);
        if (n <= 0)
            continue;
        target[n] = '\0';
        const char *base = strrchr(target, '/');
        base = base != NULL ? base + 1 : target;
        if (strncmp(base, "gnome-user-share", 16) == 0) {
            add_share(out, GAUDIT_SHARE_GNOME, base, publicshare);
            seen = 1;
        }
    }
    closedir(d);
}

void gaudit_share_services_find(const gaudit_share_where *where, gaudit_share_services *out)
{
    memset(out, 0, sizeof *out);
    char usershare_dir[512] = "/var/lib/samba/usershares";
    read_smb_conf(where->smb_conf != NULL ? where->smb_conf : "/etc/samba/smb.conf",
                  where->home != NULL ? where->home : "", out, usershare_dir,
                  sizeof usershare_dir);
    read_usershares(usershare_dir, out);
    if (where->publicshare != NULL && where->publicshare[0] == '/')
        read_gnome_user_share(where->proc != NULL ? where->proc : "/proc", where->uid,
                              where->publicshare, out);
}
