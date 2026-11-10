/* SPDX-License-Identifier: GPL-3.0-only */
#include "dpkg.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_VERSION  256
#define MAX_PACKAGES 100000

int gaudit_deb_present(const char *status_file, const char *dpkg_bin)
{
    struct stat st;
    return status_file != NULL && dpkg_bin != NULL
        && stat(status_file, &st) == 0 && S_ISREG(st.st_mode)
        && access(status_file, R_OK) == 0 && access(dpkg_bin, X_OK) == 0;
}

/* --- Version comparison (the algorithm of dpkg's verrevcmp) --------------- */

static int order(int c)
{
    if (isdigit(c))
        return 0;
    if (isalpha(c))
        return c;
    if (c == '~')
        return -1;
    if (c != 0)
        return c + 256;
    return 0;
}

static int verrevcmp(const char *a, const char *b)
{
    while (*a != '\0' || *b != '\0') {
        int first_diff = 0;

        while ((*a != '\0' && !isdigit((unsigned char)*a))
               || (*b != '\0' && !isdigit((unsigned char)*b))) {
            int ac = order((unsigned char)*a);
            int bc = order((unsigned char)*b);
            if (ac != bc)
                return ac - bc;
            a++;
            b++;
        }
        while (*a == '0')
            a++;
        while (*b == '0')
            b++;
        while (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
            if (first_diff == 0)
                first_diff = *a - *b;
            a++;
            b++;
        }
        if (isdigit((unsigned char)*a))
            return 1;
        if (isdigit((unsigned char)*b))
            return -1;
        if (first_diff != 0)
            return first_diff;
    }
    return 0;
}

static void split_version(const char *v, long *epoch,
                          char *upstream, size_t ulen, char *revision, size_t rlen)
{
    const char *colon = strchr(v, ':');
    *epoch = 0;
    if (colon != NULL) {
        *epoch = strtol(v, NULL, 10);
        v = colon + 1;
    }
    const char *hyphen = strrchr(v, '-');
    size_t n = hyphen != NULL ? (size_t)(hyphen - v) : strlen(v);
    if (n >= ulen)
        n = ulen - 1;
    memcpy(upstream, v, n);
    upstream[n] = '\0';
    snprintf(revision, rlen, "%s", hyphen != NULL ? hyphen + 1 : "");
}

int gaudit_deb_version_compare(const char *a, const char *b)
{
    long ea, eb;
    char ua[MAX_VERSION], ra[MAX_VERSION], ub[MAX_VERSION], rb[MAX_VERSION];

    split_version(a, &ea, ua, sizeof ua, ra, sizeof ra);
    split_version(b, &eb, ub, sizeof ub, rb, sizeof rb);
    if (ea != eb)
        return ea < eb ? -1 : 1;
    int c = verrevcmp(ua, ub);
    if (c != 0)
        return c < 0 ? -1 : 1;
    c = verrevcmp(ra, rb);
    return c < 0 ? -1 : c > 0;
}

/* --- Control-file stanzas ------------------------------------------------- */

typedef struct {
    char package[256];
    char arch[64];
    char version[MAX_VERSION];
    char status[128];
    int phased;  /* Phased-Update-Percentage, -1 if absent */
} stanza;

typedef int (*stanza_fn)(const stanza *s, void *ctx);  /* 0: go on, -1: abort */

static int copy_field(const char *line, const char *name, char *dst, size_t len)
{
    size_t n = strlen(name);
    if (strncmp(line, name, n) != 0)
        return 0;
    const char *v = line + n;
    while (*v == ' ' || *v == '\t')
        v++;
    size_t m = strcspn(v, "\r\n");
    if (m >= len)
        m = len - 1;
    memcpy(dst, v, m);
    dst[m] = '\0';
    return 1;
}

static void stanza_reset(stanza *s)
{
    memset(s, 0, sizeof *s);
    s->phased = -1;
}

static int read_stanzas(const char *path, stanza_fn fn, void *ctx)
{
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return -1;

    char *line = NULL;
    size_t cap = 0;
    stanza s;
    int have = 0, rc = 0;
    stanza_reset(&s);

    while (getline(&line, &cap, f) >= 0) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') {
            if (have && fn(&s, ctx) != 0) {
                rc = -1;
                break;
            }
            stanza_reset(&s);
            have = 0;
            continue;
        }
        if (line[0] == ' ' || line[0] == '\t')
            continue;  /* continuation line */
        have = 1;

        char phased[16];
        if (copy_field(line, "Package:", s.package, sizeof s.package)
            || copy_field(line, "Architecture:", s.arch, sizeof s.arch)
            || copy_field(line, "Version:", s.version, sizeof s.version)
            || copy_field(line, "Status:", s.status, sizeof s.status))
            continue;
        if (copy_field(line, "Phased-Update-Percentage:", phased, sizeof phased))
            s.phased = atoi(phased);
    }
    if (rc == 0 && have && fn(&s, ctx) != 0)
        rc = -1;
    if (ferror(f))
        rc = -1;
    free(line);
    fclose(f);
    return rc;
}

/* --- Sources (one per package index) ------------------------------------- */

/* What apt knows about the source of a package index: from the list file
 * name ("<host>_..._dists_<suite>_<component>_binary-<arch>_Packages") and
 * the suite's InRelease/Release file. */
typedef struct {
    char host[128];
    char suite[64];      /* a= */
    char codename[64];   /* n= */
    char version[32];    /* v= */
    char origin[64];     /* o= */
    char label[64];      /* l= */
    char component[64];  /* c= */
    char arch[32];       /* b= */
    int not_automatic;
    int but_automatic_upgrades;
} source_info;

static void copy_span(char *dst, size_t len, const char *from, const char *to)
{
    size_t n = to > from ? (size_t)(to - from) : 0;
    if (n >= len)
        n = len - 1;
    memcpy(dst, from, n);
    dst[n] = '\0';
}

static void read_release(const char *lists_dir, const char *packages_name,
                         const char *suite_end, source_info *src)
{
    int prefix_len = (int)(suite_end - packages_name) + 1;
    static const char *const release_names[] = { "InRelease", "Release" };

    for (size_t i = 0; i < 2; i++) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%.*s%s",
                         lists_dir, prefix_len, packages_name, release_names[i]);
        if (n < 0 || (size_t)n >= sizeof path)
            return;
        FILE *f = fopen(path, "re");
        if (f == NULL)
            continue;
        char line[512], flag[16];
        while (fgets(line, sizeof line, f) != NULL) {
            if (strncmp(line, "-----BEGIN PGP SIGNATURE", 24) == 0)
                break;
            if (line[0] == ' ')
                continue;  /* checksum lists */
            if (copy_field(line, "Origin:", src->origin, sizeof src->origin)
                || copy_field(line, "Label:", src->label, sizeof src->label)
                || copy_field(line, "Suite:", src->suite, sizeof src->suite)
                || copy_field(line, "Codename:", src->codename, sizeof src->codename)
                || copy_field(line, "Version:", src->version, sizeof src->version))
                continue;
            if (copy_field(line, "NotAutomatic:", flag, sizeof flag))
                src->not_automatic = strcmp(flag, "yes") == 0;
            else if (copy_field(line, "ButAutomaticUpgrades:", flag, sizeof flag))
                src->but_automatic_upgrades = strcmp(flag, "yes") == 0;
        }
        fclose(f);
        return;
    }
}

static void source_from_list(const char *lists_dir, const char *name, source_info *src)
{
    memset(src, 0, sizeof *src);

    const char *host_end = strchr(name, '_');
    copy_span(src->host, sizeof src->host, name, host_end ? host_end : name + strlen(name));

    const char *arch = strstr(name, "_binary-");
    const char *arch_end = strstr(name, "_Packages");
    if (arch != NULL && arch_end != NULL && arch_end > arch)
        copy_span(src->arch, sizeof src->arch, arch + strlen("_binary-"), arch_end);

    const char *dists = strstr(name, "_dists_");
    if (dists == NULL)
        return;  /* flat repository: no suite, component or Release file */
    const char *suite = dists + strlen("_dists_");
    const char *suite_end = strchr(suite, '_');
    if (suite_end == NULL)
        return;
    copy_span(src->suite, sizeof src->suite, suite, suite_end);
    if (arch != NULL && arch > suite_end)
        copy_span(src->component, sizeof src->component, suite_end + 1, arch);

    read_release(lists_dir, name, suite_end, src);  /* may refine suite */
}

static int default_priority(const source_info *src)
{
    if (src->not_automatic)
        return src->but_automatic_upgrades ? 100 : 1;
    return 500;
}

/* --- apt preferences (pinning) ------------------------------------------- */

#define MAX_PINS     256
#define MAX_CRITERIA 8

typedef enum { PIN_VERSION, PIN_ORIGIN, PIN_RELEASE } pin_kind;

typedef struct {
    char key;  /* a n v o l c b */
    char value[128];
} criterion;

typedef struct {
    char packages[512];  /* space-separated glob patterns */
    int general;         /* "Package: *" */
    pin_kind kind;
    char value[256];     /* version glob or origin host */
    criterion crit[MAX_CRITERIA];
    int n_crit;
    int priority;
} pin;

typedef struct {
    pin items[MAX_PINS];
    size_t len;
} pin_list;

static void strip(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
    size_t start = 0;
    while (isspace((unsigned char)s[start]))
        start++;
    if (s[start] == '"' && len - start >= 2 && s[len - 1] == '"') {
        s[len - 1] = '\0';
        start++;
    }
    memmove(s, s + start, strlen(s + start) + 1);
}

/* 0 ok, -1 unsupported. */
static int parse_pin_value(pin *p, const char *value)
{
    char buf[512];
    snprintf(buf, sizeof buf, "%s", value);

    if (strncmp(buf, "version ", 8) == 0) {
        p->kind = PIN_VERSION;
        snprintf(p->value, sizeof p->value, "%s", buf + 8);
        strip(p->value);
        return 0;
    }
    if (strncmp(buf, "origin ", 7) == 0 || strcmp(buf, "origin") == 0) {
        p->kind = PIN_ORIGIN;
        snprintf(p->value, sizeof p->value, "%s", buf + (buf[6] ? 7 : 6));
        strip(p->value);
        return 0;
    }
    if (strncmp(buf, "release ", 8) != 0)
        return -1;

    p->kind = PIN_RELEASE;
    p->n_crit = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf + 8, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        if (p->n_crit >= MAX_CRITERIA)
            return -1;
        criterion *c = &p->crit[p->n_crit];
        strip(tok);
        char *eq = strchr(tok, '=');
        if (eq == NULL) {
            c->key = 'a';  /* "release stable" means a=stable */
            snprintf(c->value, sizeof c->value, "%s", tok);
        } else {
            *eq = '\0';
            strip(tok);
            if (strlen(tok) != 1 || strchr("anvolcb", tok[0]) == NULL)
                return -1;
            c->key = tok[0];
            snprintf(c->value, sizeof c->value, "%s", eq + 1);
        }
        strip(c->value);
        p->n_crit++;
    }
    return 0;
}

/* 0 ok, -1 unsupported or invalid. */
static int finish_pin(pin_list *pins, const char *package, const char *value,
                      const char *priority, int have_any)
{
    if (!have_any)
        return 0;
    if (package[0] == '\0' || value[0] == '\0' || priority[0] == '\0')
        return -1;
    if (pins->len >= MAX_PINS)
        return -1;

    pin *p = &pins->items[pins->len];
    memset(p, 0, sizeof *p);
    snprintf(p->packages, sizeof p->packages, "%s", package);
    strip(p->packages);
    if (strchr(p->packages, '/') != NULL)
        return -1;  /* regex package patterns are not supported */
    p->general = strcmp(p->packages, "*") == 0;
    if (parse_pin_value(p, value) != 0)
        return -1;

    char *end;
    long prio = strtol(priority, &end, 10);
    while (isspace((unsigned char)*end))
        end++;
    if (end == priority || *end != '\0')
        return -1;
    p->priority = (int)prio;
    pins->len++;
    return 0;
}

/* 0 ok (missing file is fine), -1 cannot tell. */
static int read_prefs_file(const char *path, pin_list *pins)
{
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return errno == ENOENT ? 0 : -1;

    char line[1024];
    char package[512] = "", value[512] = "", priority[32] = "";
    int have_any = 0, rc = 0;

    while (fgets(line, sizeof line, f) != NULL) {
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#')
            continue;
        if (*s == '\n' || *s == '\r' || *s == '\0') {
            if (finish_pin(pins, package, value, priority, have_any) != 0) {
                rc = -1;
                break;
            }
            package[0] = value[0] = priority[0] = '\0';
            have_any = 0;
            continue;
        }
        if (line[0] == ' ' || line[0] == '\t')
            continue;  /* continuation (e.g. long Explanation) */
        have_any = 1;
        if (copy_field(s, "Package:", package, sizeof package)
            || copy_field(s, "Pin:", value, sizeof value)
            || copy_field(s, "Pin-Priority:", priority, sizeof priority))
            continue;
        if (strncmp(s, "Explanation:", 12) == 0)
            continue;
        rc = -1;  /* unknown field */
        break;
    }
    if (rc == 0 && finish_pin(pins, package, value, priority, have_any) != 0)
        rc = -1;
    fclose(f);
    return rc;
}

/* apt reads files in preferences.d without an extension or ending in ".pref". */
static int prefs_name_allowed(const struct dirent *entry)
{
    const char *name = entry->d_name;
    if (name[0] == '.')
        return 0;
    for (const char *p = name; *p != '\0'; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    const char *dot = strrchr(name, '.');
    return dot == NULL || strcmp(dot, ".pref") == 0;
}

static int compare_entries(const struct dirent **a, const struct dirent **b)
{
    return strcmp((*a)->d_name, (*b)->d_name);
}

static int read_prefs(const char *prefs_file, const char *prefs_dir, pin_list *pins)
{
    pins->len = 0;
    int rc = 0;

    if (prefs_dir != NULL) {
        struct dirent **entries = NULL;
        int n = scandir(prefs_dir, &entries, prefs_name_allowed, compare_entries);
        if (n < 0 && errno != ENOENT)
            return -1;
        for (int i = 0; i < n; i++) {
            char path[PATH_MAX];
            int len = snprintf(path, sizeof path, "%s/%s", prefs_dir, entries[i]->d_name);
            if (rc == 0 && (len < 0 || (size_t)len >= sizeof path || read_prefs_file(path, pins) != 0))
                rc = -1;
            free(entries[i]);
        }
        free(entries);
    }
    if (rc == 0 && prefs_file != NULL && read_prefs_file(prefs_file, pins) != 0)
        rc = -1;
    return rc;
}

static int package_matches(const pin *p, const char *name)
{
    char buf[512];
    snprintf(buf, sizeof buf, "%s", p->packages);
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t", &save); tok != NULL; tok = strtok_r(NULL, " \t", &save))
        if (fnmatch(tok, name, 0) == 0)
            return 1;
    return 0;
}

static const char *source_field(const source_info *src, char key)
{
    switch (key) {
    case 'a': return src->suite;
    case 'n': return src->codename;
    case 'v': return src->version;
    case 'o': return src->origin;
    case 'l': return src->label;
    case 'c': return src->component;
    case 'b': return src->arch;
    default:  return "";
    }
}

/* src NULL: the version is only known from the dpkg status file. */
static int pin_matches(const pin *p, const char *name, const char *version,
                       const source_info *src)
{
    if (!p->general && !package_matches(p, name))
        return 0;
    switch (p->kind) {
    case PIN_VERSION:
        return fnmatch(p->value, version, 0) == 0;
    case PIN_ORIGIN:
        if (src == NULL)
            return p->value[0] == '\0';
        return fnmatch(p->value, src->host, 0) == 0;
    case PIN_RELEASE:
        if (src == NULL)
            return 0;
        for (int i = 0; i < p->n_crit; i++)
            if (fnmatch(p->crit[i].value, source_field(src, p->crit[i].key), 0) != 0)
                return 0;
        return 1;
    }
    return 0;
}

/* Specific records before general ones; the first match wins. */
static int version_priority(const pin_list *pins, const char *name, const char *version,
                            const source_info *src, int fallback)
{
    for (int pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < pins->len; i++) {
            const pin *p = &pins->items[i];
            if (p->general == pass && pin_matches(p, name, version, src))
                return p->priority;
        }
    return fallback;
}

/* --- Installed packages --------------------------------------------------- */

typedef struct {
    char *name;
    char *arch;
    char *version;
    int same;           /* the installed version is offered by some source */
    int installed_prio; /* priority of the installed version */
    int has_newer;      /* some installable newer version exists */
    int newer_prio;     /* highest priority among those */
} entry;

typedef struct {
    entry *items;
    size_t len, cap;
} entry_list;

static int entry_cmp(const void *a, const void *b)
{
    const entry *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    return c != 0 ? c : strcmp(x->arch, y->arch);
}

static int is_installed(const char *status)
{
    const char *last = strrchr(status, ' ');
    return last != NULL && strcmp(last + 1, "installed") == 0;
}

static int collect_installed(const stanza *s, void *ctx)
{
    entry_list *l = ctx;
    if (s->package[0] == '\0' || s->version[0] == '\0' || !is_installed(s->status))
        return 0;
    if (l->len >= MAX_PACKAGES)
        return -1;
    if (l->len == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 1024;
        entry *items = realloc(l->items, cap * sizeof *items);
        if (items == NULL)
            return -1;
        l->items = items;
        l->cap = cap;
    }
    entry *e = &l->items[l->len];
    memset(e, 0, sizeof *e);
    e->name = strdup(s->package);
    e->arch = strdup(s->arch);
    e->version = strdup(s->version);
    if (e->name == NULL || e->arch == NULL || e->version == NULL) {
        free(e->name);
        free(e->arch);
        free(e->version);
        return -1;
    }
    l->len++;
    return 0;
}

static void free_entries(entry_list *l)
{
    for (size_t i = 0; i < l->len; i++) {
        free(l->items[i].name);
        free(l->items[i].arch);
        free(l->items[i].version);
    }
    free(l->items);
}

/* --- Package indexes ------------------------------------------------------ */

typedef struct {
    entry_list *installed;
    const pin_list *pins;
    const source_info *src;
} index_ctx;

static int match_available(const stanza *s, void *vctx)
{
    index_ctx *ctx = vctx;
    if (s->package[0] == '\0' || s->version[0] == '\0' || ctx->installed->len == 0)
        return 0;

    entry key = { .name = (char *)s->package, .arch = (char *)s->arch };
    entry *e = bsearch(&key, ctx->installed->items, ctx->installed->len,
                       sizeof *e, entry_cmp);
    if (e == NULL)
        return 0;

    int prio = version_priority(ctx->pins, s->package, s->version, ctx->src,
                                default_priority(ctx->src));
    int c = gaudit_deb_version_compare(s->version, e->version);
    if (c == 0) {
        e->same = 1;
        if (prio > e->installed_prio)
            e->installed_prio = prio;
    } else if (c > 0) {
        /* Never installable when pinned below 0, and phased updates are held
         * back until they reach everyone. Downgrades (c < 0) are not counted. */
        int held = s->phased >= 0 && s->phased < 100;
        if (prio >= 0 && !held && (!e->has_newer || prio > e->newer_prio)) {
            e->has_newer = 1;
            e->newer_prio = prio;
        }
    }
    return 0;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t len = strlen(s), slen = strlen(suffix);
    return len >= slen && strcmp(s + len - slen, suffix) == 0;
}

/* Kernel ABI "N.N.N-N" at p. */
static int kernel_abi_at(const char *p)
{
    for (int part = 0; part < 4; part++) {
        if (!isdigit((unsigned char)*p))
            return 0;
        while (isdigit((unsigned char)*p))
            p++;
        if (part < 2) {
            if (*p != '.')
                return 0;
            p++;
        } else if (part == 2) {
            if (*p != '-')
                return 0;
            p++;
        }
    }
    return 1;
}

/* e.g. linux-image-6.8.0-40-generic, linux-hwe-6.8-headers-6.8.0-40 */
static int versioned_kernel_package(const char *name)
{
    if (strncmp(name, "linux-", 6) != 0)
        return 0;
    for (const char *p = name; *p != '\0'; p++)
        if (kernel_abi_at(p))
            return 1;
    return 0;
}

gaudit_backend_status gaudit_deb_scan(const char *status_file, const char *lists_dir,
                                      const char *prefs_file, const char *prefs_dir,
                                      gaudit_deb_counts *out)
{
    return gaudit_deb_scan_ex(status_file, lists_dir, prefs_file, prefs_dir, out, NULL, NULL);
}

gaudit_backend_status gaudit_deb_scan_ex(const char *status_file, const char *lists_dir,
                                         const char *prefs_file, const char *prefs_dir,
                                         gaudit_deb_counts *out,
                                         gaudit_deb_package_fn on_obsolete, void *cb_ctx)
{
    if (status_file == NULL || lists_dir == NULL || out == NULL)
        return GAUDIT_BACKEND_ERROR;

    entry_list installed = { 0 };
    pin_list *pins = calloc(1, sizeof *pins);
    gaudit_backend_status status = GAUDIT_BACKEND_OK;

    if (pins == NULL || read_prefs(prefs_file, prefs_dir, pins) != 0) {
        status = GAUDIT_BACKEND_ERROR;  /* pinning we cannot follow: no guess */
        goto done;
    }
    if (read_stanzas(status_file, collect_installed, &installed) != 0) {
        status = GAUDIT_BACKEND_ERROR;
        goto done;
    }
    for (size_t i = 0; i < installed.len; i++) {
        entry *e = &installed.items[i];
        e->installed_prio = version_priority(pins, e->name, e->version, NULL, 100);
    }
    if (installed.len > 0)
        qsort(installed.items, installed.len, sizeof *installed.items, entry_cmp);

    DIR *dir = opendir(lists_dir);
    if (dir == NULL) {
        status = GAUDIT_BACKEND_UNAVAILABLE;
        goto done;
    }
    unsigned indexes = 0, compressed = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strstr(de->d_name, "_Packages.") != NULL) {
            compressed++;  /* _Packages.lz4 etc. are not read */
            continue;
        }
        if (!ends_with(de->d_name, "_Packages"))
            continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s", lists_dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof path) {
            status = GAUDIT_BACKEND_ERROR;
            break;
        }
        source_info src;
        source_from_list(lists_dir, de->d_name, &src);
        index_ctx ctx = { &installed, pins, &src };
        if (read_stanzas(path, match_available, &ctx) != 0) {
            status = GAUDIT_BACKEND_ERROR;
            break;
        }
        indexes++;
    }
    closedir(dir);

    /* Partly compressed indexes would make packages from those sources look
     * obsolete; say "unknown" rather than give wrong counts. */
    if (status == GAUDIT_BACKEND_OK && (indexes == 0 || compressed > 0))
        status = GAUDIT_BACKEND_UNAVAILABLE;
    if (status != GAUDIT_BACKEND_OK)
        goto done;

    out->obsolete = 0;
    out->upgradable = 0;
    for (size_t i = 0; i < installed.len; i++) {
        const entry *e = &installed.items[i];
        /* Highest priority wins; on a tie the higher version wins. */
        int upgradable = e->has_newer && e->newer_prio >= e->installed_prio;
        if (upgradable)
            out->upgradable++;
        /* As apt's "local": the installed version is not offered anywhere
         * and no upgrade will replace it. */
        if (!e->same && !upgradable && !versioned_kernel_package(e->name)) {
            out->obsolete++;
            if (on_obsolete != NULL)
                on_obsolete(e->name, e->arch, e->version, cb_ctx);
        }
    }

done:
    free_entries(&installed);
    free(pins);
    return status;
}
