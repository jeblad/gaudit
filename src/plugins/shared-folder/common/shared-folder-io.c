/* SPDX-License-Identifier: GPL-3.0-only */
#include "shared-folder.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 2048

static int done(int n, size_t len)
{
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_shared_format_config(const gaudit_shared_config *c, char *buf, size_t len)
{
    char standard[sizeof c->standard * 2 + 3], locale[sizeof c->locale * 2 + 3],
        def[sizeof c->default_name * 2 + 3];
    if (c->state < 0 || c->state > 3 || gaudit_probe_quote(standard, sizeof standard, c->standard) != 0
        || gaudit_probe_quote(locale, sizeof locale, c->locale) != 0
        || gaudit_probe_quote(def, sizeof def, c->default_name) != 0)
        return -1;
    return done(snprintf(buf, len,
                         "(shared-config (state %d) (standard %s) (exists %d) (locale %s) (default %s)"
                         " (names %u))\n",
                         c->state, standard, c->exists ? 1 : 0, locale, def, c->names), len);
}

int gaudit_shared_format_folder(const gaudit_shared_folder *f, char *buf, size_t len)
{
    char name[sizeof f->name * 2 + 3], lang[sizeof f->lang * 2 + 3], target[sizeof f->target * 2 + 3];
    if (f->name[0] == '\0' || strchr(f->name, '/') != NULL || f->entries < -2 || f->entries > 1000
        || gaudit_probe_quote(name, sizeof name, f->name) != 0
        || gaudit_probe_quote(lang, sizeof lang, f->lang) != 0
        || gaudit_probe_quote(target, sizeof target, f->target) != 0)
        return -1;
    return done(snprintf(buf, len,
                         "(shared-folder (name %s) (lang %s) (machine %d) (current %d) (standard %d)"
                         " (link %d) (target %s) (case %d) (entries %ld))\n",
                         name, lang, f->machine ? 1 : 0, f->current ? 1 : 0, f->standard ? 1 : 0,
                         f->link ? 1 : 0, target, f->case_differs ? 1 : 0, f->entries), len);
}

static int known_kind(const char *k)
{
    return strcmp(k, "samba") == 0 || strcmp(k, "samba-user") == 0 || strcmp(k, "gnome") == 0;
}

int gaudit_shared_format_service(const gaudit_shared_service *s, char *buf, size_t len)
{
    char name[sizeof s->name * 2 + 3], path[sizeof s->path * 2 + 3];
    if (!known_kind(s->kind) || s->path[0] != '/' || gaudit_probe_quote(name, sizeof name, s->name) != 0
        || gaudit_probe_quote(path, sizeof path, s->path) != 0)
        return -1;
    return done(snprintf(buf, len, "(shared-service (kind \"%s\") (name %s) (path %s))\n", s->kind,
                         name, path), len);
}

int gaudit_shared_format_end(const gaudit_shared_end *e, char *buf, size_t len)
{
    return done(snprintf(buf, len, "(shared-end (folders %u) (services %u) (more %d) (usershares %d))\n",
                         e->folders, e->services, e->more ? 1 : 0, e->usershares ? 1 : 0), len);
}

/* The line without its newline, in copy; -1 when it is not one line. */
static int one_line(const char *line, char *copy)
{
    if (line == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    memcpy(copy, line, len);
    copy[len] = '\0';
    return 0;
}

int gaudit_shared_parse_line(const char *line, gaudit_shared_config *c, gaudit_shared_folder *f,
                             gaudit_shared_service *s, gaudit_shared_end *e)
{
    char copy[MAX_LINE];
    if (one_line(line, copy) != 0)
        return -1;
    long long a, b, d, g, h, i, j, k;
    gaudit_shared_config cc = { 0 };
    const gaudit_sexpr_field config[] = {
        { .key = "state", .value = &a, .max = 3 },
        { .key = "standard", .text = cc.standard, .text_len = sizeof cc.standard },
        { .key = "exists", .value = &b, .max = 1 },
        { .key = "locale", .text = cc.locale, .text_len = sizeof cc.locale },
        { .key = "default", .text = cc.default_name, .text_len = sizeof cc.default_name },
        { .key = "names", .value = &d, .max = 100000 },
    };
    if (gaudit_sexpr_parse(copy, "shared-config", config, 6) == 0) {
        cc.state = (int)a;
        cc.exists = (int)b;
        cc.names = (unsigned)d;
        if (cc.state == 1 && cc.standard[0] != '/' && strncmp(cc.standard, "~/", 2) != 0)
            return -1;
        if (c != NULL)
            *c = cc;
        return GAUDIT_SHARED_LINE_CONFIG;
    }
    gaudit_shared_folder ff = { 0 };
    const gaudit_sexpr_field folder[] = {
        { .key = "name", .text = ff.name, .text_len = sizeof ff.name },
        { .key = "lang", .text = ff.lang, .text_len = sizeof ff.lang },
        { .key = "machine", .value = &a, .max = 1 },
        { .key = "current", .value = &b, .max = 1 },
        { .key = "standard", .value = &d, .max = 1 },
        { .key = "link", .value = &g, .max = 1 },
        { .key = "target", .text = ff.target, .text_len = sizeof ff.target },
        { .key = "case", .value = &h, .max = 1 },
        { .key = "entries", .value = &i, .min = -2, .max = 1000 },
    };
    if (gaudit_sexpr_parse(copy, "shared-folder", folder, 9) == 0) {
        if (ff.name[0] == '\0' || strchr(ff.name, '/') != NULL || strcmp(ff.name, ".") == 0
            || strcmp(ff.name, "..") == 0)
            return -1;
        ff.machine = (int)a;
        ff.current = (int)b;
        ff.standard = (int)d;
        ff.link = (int)g;
        ff.case_differs = (int)h;
        ff.entries = (long)i;
        if (f != NULL)
            *f = ff;
        return GAUDIT_SHARED_LINE_FOLDER;
    }
    gaudit_shared_service ss = { 0 };
    const gaudit_sexpr_field service[] = {
        { .key = "kind", .text = ss.kind, .text_len = sizeof ss.kind },
        { .key = "name", .text = ss.name, .text_len = sizeof ss.name },
        { .key = "path", .text = ss.path, .text_len = sizeof ss.path },
    };
    if (gaudit_sexpr_parse(copy, "shared-service", service, 3) == 0) {
        if (!known_kind(ss.kind) || ss.path[0] != '/')
            return -1;
        if (s != NULL)
            *s = ss;
        return GAUDIT_SHARED_LINE_SERVICE;
    }
    const gaudit_sexpr_field end[] = {
        { .key = "folders", .value = &j, .max = 1000 },
        { .key = "services", .value = &k, .max = 1000 },
        { .key = "more", .value = &a, .max = 1 },
        { .key = "usershares", .value = &b, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "shared-end", end, 4) == 0) {
        if (e != NULL)
            *e = (gaudit_shared_end){ .folders = (unsigned)j, .services = (unsigned)k,
                                      .more = (int)a, .usershares = (int)b };
        return GAUDIT_SHARED_LINE_END;
    }
    return -1;
}

int gaudit_shared_parse_tidy(const char *line, char *clash, size_t clash_len,
                             gaudit_shared_moves *moves)
{
    char copy[MAX_LINE];
    if (one_line(line, copy) != 0)
        return -1;
    char name[256];
    const gaudit_sexpr_field c[] = { { .key = "name", .text = name, .text_len = sizeof name } };
    if (gaudit_sexpr_parse(copy, "shared-clash", c, 1) == 0) {
        if (name[0] == '\0' || strchr(name, '/') != NULL)
            return -1;
        if (clash != NULL)
            snprintf(clash, clash_len, "%s", name);
        return 1;
    }
    long long r, m, k, o, f;
    const gaudit_sexpr_field mv[] = {
        { .key = "result", .value = &r, .max = 2 },
        { .key = "moved", .value = &m, .max = 1000000 },
        { .key = "clashes", .value = &k, .max = 1000000 },
        { .key = "other-disk", .value = &o, .max = 1000000 },
        { .key = "failed", .value = &f, .max = 1000000 },
    };
    if (gaudit_sexpr_parse(copy, "shared-moves", mv, 5) == 0) {
        if (moves != NULL)
            *moves = (gaudit_shared_moves){ .result = (int)r, .moved = (unsigned)m,
                                            .clashes = (unsigned)k, .other_disk = (unsigned)o,
                                            .failed = (unsigned)f };
        return 2;
    }
    const gaudit_sexpr_field rm[] = { { .key = "result", .value = &r, .max = 2 } };
    if (gaudit_sexpr_parse(copy, "shared-removed", rm, 1) == 0) {
        if (moves != NULL)
            *moves = (gaudit_shared_moves){ .result = (int)r };
        return 3;
    }
    return -1;
}

/* --- Secrets in folders for sharing ------------------------------------------- */

static int plain_word(const char *s, int empty_ok)
{
    if (*s == '\0')
        return empty_ok;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-'))
            return 0;
    return 1;
}

static int plain_path(const char *p)
{
    return p[0] == '/' || strncmp(p, "~/", 2) == 0;
}

static int copy_line(const char *line, char copy[MAX_LINE])
{
    if (line == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    memcpy(copy, line, len);
    copy[len] = '\0';
    return 0;
}

int gaudit_shared_format_secret(const gaudit_shared_secret *s, char *buf, size_t len)
{
    char path[sizeof s->path * 2 + 3], reason[sizeof s->reason * 2 + 3], by[sizeof s->by * 2 + 3];
    if (!plain_path(s->path) || !plain_word(s->reason, 0) || !plain_word(s->by, 1)
        || gaudit_probe_quote(path, sizeof path, s->path) != 0
        || gaudit_probe_quote(reason, sizeof reason, s->reason) != 0
        || gaudit_probe_quote(by, sizeof by, s->by) != 0)
        return -1;
    return done(snprintf(buf, len, "(shared-secret (path %s) (reason %s) (by %s))\n", path, reason,
                         by), len);
}

int gaudit_shared_parse_secret(const char *line, gaudit_shared_secret *s)
{
    char copy[MAX_LINE];
    if (copy_line(line, copy) != 0)
        return -1;
    gaudit_shared_secret ss = { 0 };
    const gaudit_sexpr_field f[] = {
        { .key = "path", .text = ss.path, .text_len = sizeof ss.path },
        { .key = "reason", .text = ss.reason, .text_len = sizeof ss.reason },
        { .key = "by", .text = ss.by, .text_len = sizeof ss.by },
    };
    if (gaudit_sexpr_parse(copy, "shared-secret", f, 3) != 0 || !plain_path(ss.path)
        || !plain_word(ss.reason, 0) || !plain_word(ss.by, 1))
        return -1;
    if (s != NULL)
        *s = ss;
    return 0;
}

int gaudit_shared_format_secret_scan(const gaudit_shared_secret_scan *s, char *buf, size_t len)
{
    if (s->folders > 100 || s->skipped > 100 || s->found > 1000000)
        return -1;
    return done(snprintf(buf, len,
                         "(shared-secret-scan (folders %u) (skipped %u) (found %u) (more %d) "
                         "(truncated %d))\n",
                         s->folders, s->skipped, s->found, s->more ? 1 : 0, s->truncated ? 1 : 0),
                len);
}

int gaudit_shared_parse_secret_scan(const char *line, gaudit_shared_secret_scan *s)
{
    char copy[MAX_LINE];
    if (copy_line(line, copy) != 0)
        return -1;
    long long fo, sk, fd, mo, tr;
    const gaudit_sexpr_field f[] = {
        { .key = "folders", .value = &fo, .max = 100 },
        { .key = "skipped", .value = &sk, .max = 100 },
        { .key = "found", .value = &fd, .max = 1000000 },
        { .key = "more", .value = &mo, .max = 1 },
        { .key = "truncated", .value = &tr, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "shared-secret-scan", f, 5) != 0)
        return -1;
    if (s != NULL)
        *s = (gaudit_shared_secret_scan){ (unsigned)fo, (unsigned)sk, (unsigned)fd, (int)mo, (int)tr };
    return 0;
}
