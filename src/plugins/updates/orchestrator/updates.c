/* SPDX-License-Identifier: GPL-3.0-only */
/* Facts only: how often updates are looked for, whether they are installed
 * automatically, what waits, where security updates come from, what no
 * source keeps up to date. Read directly by the backend, never through
 * an admin tool; the rule decides what is a warning. */
#include "updates-mode.h"
#include "updates.h"
#include "vendor.h"
#include "os-release.h"

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    FILE *out;
    unsigned written;
    int failed;
} sink;

static void put(sink *s, gaudit_update_key key, gaudit_fact_status status, long long value,
                const char *text)
{
    gaudit_update_fact f = { .key = key, .status = status, .value = value };
    snprintf(f.text, sizeof f.text, "%s", text != NULL ? text : "");
    char line[512];
    if (gaudit_update_format_fact(&f, line, sizeof line) != 0 || fputs(line, s->out) == EOF)
        s->failed = 1;
    else
        s->written++;
}

static gaudit_fact_status from_backend(gaudit_backend_status st)
{
    return st == GAUDIT_BACKEND_OK ? GAUDIT_FACT_KNOWN
         : st == GAUDIT_BACKEND_NOT_IMPLEMENTED ? GAUDIT_FACT_UNSUPPORTED
         : GAUDIT_FACT_UNKNOWN;
}

/* A setting from update_settings: -1 is "could not tell". */
static void put_setting(sink *s, gaudit_update_key key, int have, long long v)
{
    if (!have)
        put(s, key, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else
        put(s, key, v < 0 ? GAUDIT_FACT_UNKNOWN : GAUDIT_FACT_KNOWN, v < 0 ? 0 : v, NULL);
}

/* --- Local copies of a vendor's source ------------------------------------- */

typedef struct {
    const gaudit_vendor_local *v;
    char release[16], version[16];
    char folder[256];   /* its folder's name: also the package that put it there */
    char **keys;        /* "name\x1fversion", sorted */
    size_t n, cap;
    unsigned installed;  /* installed with a name and version the copy lists */
} local_copy;

static local_copy copies[GAUDIT_UPDATE_MAX_VENDOR];
static size_t n_copies;
static int copies_scanned;

static void copy_add(const char *name, const char *arch, const char *version, void *ctx)
{
    (void)arch;
    local_copy *c = ctx;
    if (c->n >= 20000)
        return;
    if (c->n == c->cap) {
        size_t cap = c->cap > 0 ? c->cap * 2 : 64;
        char **k = realloc(c->keys, cap * sizeof *k);
        if (k == NULL)
            return;
        c->keys = k;
        c->cap = cap;
    }
    size_t len = strlen(name) + strlen(version) + 2;
    char *key = malloc(len);
    if (key == NULL)
        return;
    snprintf(key, len, "%s\x1f%s", name, version);
    c->keys[c->n++] = key;
}

static int key_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static local_copy *copy_of(const char *name, const char *version)
{
    if (name == NULL || version == NULL)
        return NULL;
    char key[512];
    snprintf(key, sizeof key, "%s\x1f%s", name, version);
    const char *k = key;
    for (size_t i = 0; i < n_copies; i++)
        if (strcmp(name, copies[i].folder) == 0  /* the installer's own package */
            || bsearch(&k, copies[i].keys, copies[i].n, sizeof *copies[i].keys, key_cmp) != NULL)
            return &copies[i];
    return NULL;
}

static void count_installed(const char *name, const char *arch, const char *version, void *ctx)
{
    (void)arch;
    (void)ctx;
    local_copy *c = copy_of(name, version);
    if (c != NULL)
        c->installed++;
}

void gaudit_updates_local_reset(void)
{
    for (size_t i = 0; i < n_copies; i++) {
        for (size_t j = 0; j < copies[i].n; j++)
            free(copies[i].keys[j]);
        free(copies[i].keys);
    }
    memset(copies, 0, sizeof copies);
    n_copies = 0;
    copies_scanned = 0;
}

void gaudit_updates_local_scan(const gaudit_pkg_backend *pkg, const char *var_dir)
{
    if (copies_scanned)
        return;
    copies_scanned = 1;
    if (pkg == NULL || pkg->each_package == NULL || var_dir == NULL)
        return;
    DIR *d = opendir(var_dir);
    if (d == NULL)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n_copies < GAUDIT_UPDATE_MAX_VENDOR) {
        local_copy c = { 0 };
        c.v = gaudit_vendor_local_match(de->d_name, c.release, sizeof c.release, c.version,
                                        sizeof c.version);
        if (c.v == NULL)
            continue;
        /* A folder of root's, never a link; its own index, plain. */
        char dir[1024], index[1100];
        struct stat st;
        snprintf(dir, sizeof dir, "%s/%s", var_dir, de->d_name);
        snprintf(index, sizeof index, "%s/Packages", dir);
        if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || lstat(index, &st) != 0
            || !S_ISREG(st.st_mode))
            continue;
        if (pkg->each_package(index, copy_add, &c) != GAUDIT_BACKEND_OK || c.n == 0) {
            for (size_t j = 0; j < c.n; j++)
                free(c.keys[j]);
            free(c.keys);
            continue;
        }
        qsort(c.keys, c.n, sizeof *c.keys, key_cmp);
        snprintf(c.folder, sizeof c.folder, "%s", de->d_name);
        copies[n_copies++] = c;
    }
    closedir(d);
    if (n_copies > 0)
        pkg->each_package(NULL, count_installed, NULL);
}

int gaudit_updates_from_local(const char *name, const char *version)
{
    return copy_of(name, version) != NULL;
}

/* The release before the one running, by distro-info's table (versions in
 * order, oldest first): "" when it cannot be told. */
static void previous_release(const gaudit_os_release *os, char *out, size_t len)
{
    out[0] = '\0';
    char path[128];
    if (strcmp(os->id, "ubuntu") != 0 && strcmp(os->id, "debian") != 0)
        return;
    snprintf(path, sizeof path, "/usr/share/distro-info/%s.csv", os->id);
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return;
    char line[512], last[32] = "";
    while (fgets(line, sizeof line, f) != NULL) {
        char version[32];
        snprintf(version, sizeof version, "%.*s", (int)strcspn(line, " ,\r\n"), line);
        if (version[0] < '0' || version[0] > '9')
            continue;  /* the header, or a release without a version (sid) */
        if (strcmp(version, os->version_id) == 0) {
            if (last[0] != '\0')
                gaudit_vendor_release_id(os->id, last, out, len);
            break;
        }
        snprintf(last, sizeof last, "%s", version);
    }
    fclose(f);
}

/* Known vendor packages (vendor.h) are taken out of the groups: they get
 * a group, and a line each, of their own. */
typedef struct {
    const gaudit_pkg_backend *pkg;
    unsigned groups[GAUDIT_SOURCELESS_GROUPS];
    unsigned vendors;
    unsigned locals;   /* without a source, but from a local copy of a vendor's source */
    gaudit_update_vendor vendor[GAUDIT_UPDATE_MAX_VENDOR];
    unsigned companions;  /* kept up to date by another program */
    gaudit_update_companion companion[GAUDIT_UPDATE_MAX_VENDOR];
} group_ctx;

/* Whether the program that manages c is installed: its Flatpak app, for
 * the system or for this user, or its own package. */
static const char *flatpak_system = "/var/lib/flatpak";
static const char *flatpak_home;  /* NULL: the user's own, by the password database */

void gaudit_updates_flatpak_dirs(const char *system, const char *home)
{
    flatpak_system = system;
    flatpak_home = home;
}

static int manager_present(const gaudit_pkg_backend *pkg, const gaudit_vendor_companion *c)
{
    char path[1024];
    struct stat st;
    if (c->flatpak != NULL) {
        snprintf(path, sizeof path, "%s/app/%s/current", flatpak_system, c->flatpak);
        if (lstat(path, &st) == 0)
            return 1;
        const char *home = flatpak_home;
        struct passwd *pw = home == NULL ? getpwuid(getuid()) : NULL;
        if (home == NULL && pw != NULL)
            home = pw->pw_dir;
        if (home != NULL) {
            snprintf(path, sizeof path, "%s/.local/share/flatpak/app/%s/current", home, c->flatpak);
            if (lstat(path, &st) == 0)
                return 1;
        }
    }
    gaudit_package_details d;
    return c->deb != NULL && pkg->package_details != NULL
           && pkg->package_details(c->deb, NULL, &d) == GAUDIT_BACKEND_OK && d.version[0] != '\0';
}

const gaudit_vendor_companion *gaudit_updates_companion_of(const gaudit_pkg_backend *pkg,
                                                           const char *name, const char *arch)
{
    if (pkg == NULL || pkg->package_details == NULL || !gaudit_vendor_companion_name_known(name))
        return NULL;
    gaudit_package_details d;
    if (pkg->package_details(name, arch, &d) != GAUDIT_BACKEND_OK)
        return NULL;
    return gaudit_vendor_companion_match(name, d.maintainer);
}

const gaudit_vendor_package *gaudit_updates_vendor_of(const gaudit_pkg_backend *pkg,
                                                      const char *name, const char *arch,
                                                      gaudit_sourceless_group group)
{
    /* Offered by a source in a lower version: then it has a source. */
    if (pkg == NULL || pkg->package_details == NULL || name == NULL
        || group == GAUDIT_SOURCELESS_ABOVE_SOURCE)
        return NULL;
    /* The name first: the details are read only for a name in the table. */
    if (!gaudit_vendor_name_known(name))
        return NULL;
    gaudit_package_details d;
    if (pkg->package_details(name, arch, &d) != GAUDIT_BACKEND_OK)
        return NULL;
    return gaudit_vendor_match(name, d.maintainer);
}

static void count_group(const char *name, const char *arch, const char *version,
                        gaudit_sourceless_group group, const char *offered, void *vctx)
{
    (void)offered;
    group_ctx *ctx = vctx;
    if (group < 0 || group >= GAUDIT_SOURCELESS_GROUPS)
        return;
    if (copy_of(name, version) != NULL) {
        ctx->locals++;
        return;
    }
    const gaudit_vendor_companion *c = gaudit_updates_companion_of(ctx->pkg, name, arch);
    if (c != NULL) {
        if (ctx->companions < GAUDIT_UPDATE_MAX_VENDOR) {
            gaudit_update_companion *out = &ctx->companion[ctx->companions];
            snprintf(out->id, sizeof out->id, "%s", c->id);
            snprintf(out->package, sizeof out->package, "%s", c->package);
            snprintf(out->manager, sizeof out->manager, "%s", c->manager);
            snprintf(out->version, sizeof out->version, "%s", version != NULL ? version : "");
            out->present = manager_present(ctx->pkg, c);
        }
        ctx->companions++;
        return;
    }
    const gaudit_vendor_package *v = gaudit_updates_vendor_of(ctx->pkg, name, arch, group);
    if (v == NULL) {
        ctx->groups[group]++;
        return;
    }
    if (ctx->vendors < GAUDIT_UPDATE_MAX_VENDOR) {
        gaudit_update_vendor *out = &ctx->vendor[ctx->vendors];
        snprintf(out->id, sizeof out->id, "%s", v->id);
        snprintf(out->title, sizeof out->title, "%s", v->title);
        snprintf(out->vendor, sizeof out->vendor, "%s", v->vendor);
        snprintf(out->version, sizeof out->version, "%s", version != NULL ? version : "");
    }
    ctx->vendors++;
}

int gaudit_updates_collect(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                           int64_t now, FILE *out)
{
    if (pkg == NULL || out == NULL)
        return 1;
    sink s = { .out = out };

    put(&s, GAUDIT_UPDATE_BACKEND, GAUDIT_FACT_KNOWN, 0, pkg->name);

    if (expected != NULL && expected != pkg)
        put(&s, GAUDIT_UPDATE_EXPECTED_MISSING, GAUDIT_FACT_KNOWN, 1,
            expected->package_system != NULL ? expected->package_system : "");
    else
        put(&s, GAUDIT_UPDATE_EXPECTED_MISSING, GAUDIT_FACT_NOT_APPLICABLE, 0, NULL);

    if (pkg->package_systems_present != NULL) {
        unsigned mask = pkg->package_systems_present();
        if (pkg->own_package_system >= 0 && pkg->own_package_system < GAUDIT_PKGSYS_COUNT)
            mask &= ~(1u << pkg->own_package_system);
        char names[128] = "";
        unsigned n = 0;
        for (int i = 0; i < GAUDIT_PKGSYS_COUNT; i++) {
            if (!(mask & (1u << i)))
                continue;
            size_t used = strlen(names);
            snprintf(names + used, sizeof names - used, "%s%s", n > 0 ? ", " : "",
                     gaudit_package_system_label((gaudit_package_system)i));
            n++;
        }
        put(&s, GAUDIT_UPDATE_OTHER_SYSTEMS, GAUDIT_FACT_KNOWN, n, names);
    } else {
        put(&s, GAUDIT_UPDATE_OTHER_SYSTEMS, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    }

    /* How updates are looked for and installed. */
    gaudit_update_settings set = { -1, -1, -1, -1, -1, -1, -1, -1, "", -1, -1, -1, "", -1, "" };
    int have = 0;
    if (pkg->update_settings != NULL && pkg->update_settings(&set) == GAUDIT_BACKEND_OK) {
        have = 1;
    } else if (pkg->automatic_updates != NULL) {
        /* Only whether they are installed automatically. */
        int on = 0;
        gaudit_backend_status st = pkg->automatic_updates(&on);
        put(&s, GAUDIT_UPDATE_INSTALL, from_backend(st), st == GAUDIT_BACKEND_OK ? on : 0, NULL);
    }
    put_setting(&s, GAUDIT_UPDATE_CHECK_DAYS, have, set.check_days);
    if (have || pkg->automatic_updates == NULL)
        put_setting(&s, GAUDIT_UPDATE_INSTALL, have, set.install);
    put_setting(&s, GAUDIT_UPDATE_DOWNLOAD, have, set.download);
    put_setting(&s, GAUDIT_UPDATE_CHECK_TIMER, have, set.check_timer);
    put_setting(&s, GAUDIT_UPDATE_INSTALL_TIMER, have, set.install_timer);
    if (!have)
        put(&s, GAUDIT_UPDATE_LAST_INSTALL, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else if (set.last_install < 0 || set.last_install > now)
        put(&s, GAUDIT_UPDATE_LAST_INSTALL, GAUDIT_FACT_UNKNOWN, 0, NULL);  /* future: unknown */
    else
        put(&s, GAUDIT_UPDATE_LAST_INSTALL, GAUDIT_FACT_KNOWN,
            set.last_install == 0 ? -1 : now - set.last_install, NULL);
    if (!have)
        put(&s, GAUDIT_UPDATE_LAST_CHANGE, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else if (set.last_change <= 0 || set.last_change > now)
        put(&s, GAUDIT_UPDATE_LAST_CHANGE, GAUDIT_FACT_UNKNOWN, 0, NULL);
    else
        put(&s, GAUDIT_UPDATE_LAST_CHANGE, GAUDIT_FACT_KNOWN, now - set.last_change, NULL);
    if (!have)
        put(&s, GAUDIT_UPDATE_ADMIN_TOOLS, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else
        put(&s, GAUDIT_UPDATE_ADMIN_TOOLS, set.admin_tools < 0 ? GAUDIT_FACT_UNKNOWN : GAUDIT_FACT_KNOWN,
            set.admin_tools < 0 ? 0 : set.admin_tools, set.admin_tools < 0 ? NULL : set.admin_names);
    put_setting(&s, GAUDIT_UPDATE_OWN_SETTING, have, set.own_setting);
    put_setting(&s, GAUDIT_UPDATE_UPGRADE_UPDATES, have, set.upgrade_updates);
    if (!have)
        put(&s, GAUDIT_UPDATE_UNREAD_SOURCES, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else
        put(&s, GAUDIT_UPDATE_UNREAD_SOURCES,
            set.unread_sources < 0 ? GAUDIT_FACT_UNKNOWN : GAUDIT_FACT_KNOWN,
            set.unread_sources < 0 ? 0 : set.unread_sources,
            set.unread_sources < 0 ? NULL : set.unread_names);
    if (!have)
        put(&s, GAUDIT_UPDATE_UPGRADE_OFF, GAUDIT_FACT_UNSUPPORTED, 0, NULL);
    else
        put(&s, GAUDIT_UPDATE_UPGRADE_OFF, set.upgrade_off < 0 ? GAUDIT_FACT_UNKNOWN : GAUDIT_FACT_KNOWN,
            set.upgrade_off < 0 ? 0 : set.upgrade_off, set.upgrade_off < 0 ? NULL : set.upgrade_off_names);

    /* When updates were last looked for. */
    int64_t epoch = 0;
    gaudit_backend_status st = pkg->last_index_update != NULL ? pkg->last_index_update(&epoch)
                                                              : GAUDIT_BACKEND_NOT_IMPLEMENTED;
    if (st == GAUDIT_BACKEND_OK && epoch > now)
        st = GAUDIT_BACKEND_ERROR;
    put(&s, GAUDIT_UPDATE_INDEX_AGE, from_backend(st), st == GAUDIT_BACKEND_OK ? now - epoch : 0,
        NULL);

    /* What waits, and what no source offers. */
    unsigned obsolete = 0, upgradable = 0, security = 0;
    int security_known = 0;
    if (pkg->package_counts != NULL) {
        st = pkg->package_counts(&obsolete, &upgradable, &security);
        security_known = st == GAUDIT_BACKEND_OK;
    } else {
        st = pkg->package_state != NULL ? pkg->package_state(&obsolete, &upgradable)
                                        : GAUDIT_BACKEND_NOT_IMPLEMENTED;
    }
    gaudit_fact_status counts = from_backend(st);
    put(&s, GAUDIT_UPDATE_PENDING, counts, upgradable, NULL);
    put(&s, GAUDIT_UPDATE_PENDING_SECURITY,
        security_known ? GAUDIT_FACT_KNOWN
        : pkg->package_counts == NULL ? GAUDIT_FACT_UNSUPPORTED : counts,
        security, NULL);
    gaudit_updates_local_scan(pkg, "/var");
    group_ctx gc = { .pkg = pkg };
    unsigned *groups = gc.groups;
    gaudit_backend_status gst = pkg->sourceless_packages != NULL
        ? pkg->sourceless_packages(count_group, &gc) : GAUDIT_BACKEND_NOT_IMPLEMENTED;
    gaudit_fact_status gstatus = from_backend(gst);
    /* The groups must add up to the count, or none of them is trusted. */
    if (gst == GAUDIT_BACKEND_OK && counts == GAUDIT_FACT_KNOWN
        && groups[0] + groups[1] + groups[2] + groups[3] + gc.vendors + gc.locals + gc.companions
               != obsolete)
        gstatus = GAUDIT_FACT_UNKNOWN;
    /* The known vendor packages have their own group, so the total is the
     * rest: the list of packages without a source leaves them out too. */
    unsigned vendors = gstatus == GAUDIT_FACT_KNOWN ? gc.vendors + gc.locals + gc.companions : 0;
    put(&s, GAUDIT_UPDATE_SOURCELESS, counts, obsolete - vendors, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_ABOVE, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[0] : 0, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_LEFTOVER, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[1] : 0, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_OTHER, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[2] : 0, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_VENDOR, gstatus, vendors, NULL);
    /* The release before, by name, for the updates kept from it. */
    char before[32] = "";
    {
        gaudit_os_release os_before;
        char prev[16] = "";
        if (gaudit_os_release_read("/etc/os-release", &os_before) == 0
            || gaudit_os_release_read("/usr/lib/os-release", &os_before) == 0)
            previous_release(&os_before, prev, sizeof prev);
        gaudit_vendor_release_name(prev, before, sizeof before);
    }
    put(&s, GAUDIT_UPDATE_SOURCELESS_KEPT, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[3] : 0,
        gstatus == GAUDIT_FACT_KNOWN ? before : NULL);

    /* Where security updates come from. */
    if (pkg->security_sources == NULL) {
        put(&s, GAUDIT_UPDATE_SECURITY_OFFICIAL, GAUDIT_FACT_NOT_APPLICABLE, 0, NULL);
        put(&s, GAUDIT_UPDATE_SECURITY_MIRROR, GAUDIT_FACT_NOT_APPLICABLE, 0, NULL);
    } else {
        unsigned official = 0, mirror = 0;
        char host[64] = "";
        st = pkg->security_sources(&official, &mirror, host, sizeof host);
        gaudit_fact_status ss = from_backend(st);
        if (ss == GAUDIT_FACT_KNOWN && official == 0 && mirror == 0)
            ss = GAUDIT_FACT_NOT_APPLICABLE;  /* no security suite at all (Debian unstable) */
        put(&s, GAUDIT_UPDATE_SECURITY_OFFICIAL, ss, ss == GAUDIT_FACT_KNOWN ? official : 0, NULL);
        put(&s, GAUDIT_UPDATE_SECURITY_MIRROR, ss, ss == GAUDIT_FACT_KNOWN ? mirror : 0,
            ss == GAUDIT_FACT_KNOWN ? host : NULL);
    }

    /* One line per known vendor package, when the groups are trusted. */
    for (unsigned i = 0; gstatus == GAUDIT_FACT_KNOWN && i < gc.vendors && i < GAUDIT_UPDATE_MAX_VENDOR;
         i++) {
        char vline[1024];
        if (gaudit_update_format_vendor(&gc.vendor[i], vline, sizeof vline) != 0
            || fputs(vline, out) == EOF)
            s.failed = 1;
    }

    /* One line per package another program keeps up to date. */
    for (unsigned i = 0; gstatus == GAUDIT_FACT_KNOWN && i < gc.companions && i < GAUDIT_UPDATE_MAX_VENDOR;
         i++) {
        char cline[1024];
        if (gaudit_update_format_companion(&gc.companion[i], cline, sizeof cline) != 0
            || fputs(cline, out) == EOF)
            s.failed = 1;
    }

    /* One line per local copy of a vendor's source something came from. */
    gaudit_os_release os;
    int have_os = gaudit_os_release_read("/etc/os-release", &os) == 0
                  || gaudit_os_release_read("/usr/lib/os-release", &os) == 0;
    for (size_t i = 0; gstatus == GAUDIT_FACT_KNOWN && i < n_copies; i++) {
        if (copies[i].installed == 0)
            continue;
        gaudit_update_local l = { .packages = copies[i].installed };
        snprintf(l.id, sizeof l.id, "%s", copies[i].v->id);
        snprintf(l.title, sizeof l.title, "%s", copies[i].v->title);
        snprintf(l.vendor, sizeof l.vendor, "%s", copies[i].v->vendor);
        snprintf(l.version, sizeof l.version, "%s", copies[i].version);
        snprintf(l.made_for, sizeof l.made_for, "%s", copies[i].release);
        gaudit_vendor_release_name(l.made_for, l.made_for_name, sizeof l.made_for_name);
        if (have_os) {
            gaudit_vendor_release_id(os.id, os.version_id, l.running, sizeof l.running);
            previous_release(&os, l.previous, sizeof l.previous);
        }
        char lline[1024];
        if (gaudit_update_format_local(&l, lline, sizeof lline) != 0 || fputs(lline, out) == EOF)
            s.failed = 1;
    }

    char line[64];
    if (s.failed || gaudit_update_format_end(s.written, line, sizeof line) != 0
        || fputs(line, out) == EOF)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* --- The newest version a vendor offers, on request ---------------------- */

int gaudit_updates_latest_from(const gaudit_pkg_backend *pkg, const gaudit_vendor_package *v,
                               const char *headers, FILE *out)
{
    if (v == NULL || out == NULL)
        return 1;
    gaudit_update_latest l = { .status = 1 };
    snprintf(l.id, sizeof l.id, "%s", v->id);
    /* The version installed, of the vendor's own package only. */
    gaudit_package_details d;
    int installed = pkg != NULL && pkg->package_details != NULL
                    && pkg->package_details(v->package, NULL, &d) == GAUDIT_BACKEND_OK
                    && gaudit_vendor_match(v->package, d.maintainer) == v && d.version[0] != '\0';
    if (installed)
        snprintf(l.installed, sizeof l.installed, "%s", d.version);
    /* The first Location header, from wget (indented, on stderr) or curl. */
    for (const char *p = headers; installed && p != NULL && *p != '\0';) {
        const char *end = strchr(p, '\n');
        size_t n = end != NULL ? (size_t)(end - p) : strlen(p);
        char line[512];
        if (n < sizeof line) {
            memcpy(line, p, n);
            line[n] = '\0';
            line[strcspn(line, "\r")] = '\0';
            const char *h = line + strspn(line, " \t");
            if (strncasecmp(h, "Location:", 9) == 0) {
                h += 9;
                h += strspn(h, " \t");
                char where[256];
                snprintf(where, sizeof where, "%.*s", (int)strcspn(h, " \t"), h);
                if (gaudit_vendor_version_from(v, where, l.version, sizeof l.version)
                    && pkg->version_compare != NULL) {
                    l.status = 0;
                    l.newer = pkg->version_compare(l.version, l.installed) > 0;
                }
                break;
            }
        }
        p = end != NULL ? end + 1 : NULL;
    }
    char buf[1024];
    if (gaudit_update_format_latest(&l, buf, sizeof buf) != 0 || fputs(buf, out) == EOF)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* Runs a fetcher (argv, absolute path first) with an empty environment
 * but LC_ALL=C, at most timeout_ms; its stdout and stderr together into
 * buf, at most len - 1 bytes. watch: a file it writes, stopped as soon as
 * that grows past max_bytes (NULL: none), since wget has no limit of its
 * own. Its exit status, -1, or -2 when stopped for the size. */
static int run_fetcher(char *const argv[], char *buf, size_t len, long timeout_ms,
                       const char *watch, long long max_bytes)
{
    if (argv == NULL || buf == NULL || len == 0)
        return -1;
    buf[0] = '\0';
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        static char *const env[] = { (char *)"LC_ALL=C", NULL };
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0
            || null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(fds[1], STDOUT_FILENO) < 0
            || dup2(fds[1], STDERR_FILENO) < 0 || chdir("/") != 0)
            _exit(126);
        execve(argv[0], argv, env);
        _exit(127);
    }
    close(fds[1]);
    size_t used = 0;
    int too_large = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = timeout_ms - (long)((now.tv_sec - start.tv_sec) * 1000
                                        + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) {
            kill(pid, SIGKILL);
            break;
        }
        struct stat ws;
        if (watch != NULL && stat(watch, &ws) == 0 && ws.st_size > max_bytes) {
            kill(pid, SIGKILL);
            too_large = 1;
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        long wait = watch != NULL ? 500 : 60000;  /* look at the file twice a second */
        int r = poll(&pfd, 1, left > wait ? (int)wait : (int)left);
        if (r <= 0)
            continue;
        char chunk[1024];
        ssize_t n = read(fds[0], chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        size_t take = (size_t)n < len - 1 - used ? (size_t)n : len - 1 - used;
        memcpy(buf + used, chunk, take);
        used += take;
    }
    buf[used] = '\0';
    close(fds[0]);
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    if (too_large)
        return -2;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static const char *const WGET = "/usr/bin/wget";
static const char *const CURL = "/usr/bin/curl";

/* wget if it is there, else curl; NULL for neither. */
static const char *fetcher(void)
{
    return access(WGET, X_OK) == 0 ? WGET : access(CURL, X_OK) == 0 ? CURL : NULL;
}

/* The response headers for url, without following the redirect: no
 * configuration file, https only. 0 when a fetcher ran. */
static int fetch_headers(const char *url, char *buf, size_t len)
{
    char *const wget[] = {
        (char *)WGET, (char *)"--no-config", (char *)"--spider",
        (char *)"--server-response", (char *)"--max-redirect=0", (char *)"--https-only",
        (char *)"--tries=1", (char *)"--timeout=20", (char *)"--no-hsts", (char *)"--no-cookies",
        (char *)"--", (char *)url, NULL,
    };
    /* -q first: no .curlrc. */
    char *const curl[] = {
        (char *)CURL, (char *)"-q", (char *)"--silent", (char *)"--show-error",
        (char *)"--head", (char *)"--max-redirs", (char *)"0", (char *)"--proto", (char *)"=https",
        (char *)"--max-time", (char *)"20", (char *)"--", (char *)url, NULL,
    };
    const char *f = fetcher();
    if (f == NULL)
        return -1;
    run_fetcher(f == WGET ? wget : curl, buf, len, 30 * 1000, NULL, 0);
    return 0;  /* its exit status says nothing here: a refused redirect is an "error" */
}

int gaudit_updates_latest(const char *id)
{
    const gaudit_vendor_package *v = gaudit_vendor_find(id);
    if (v == NULL || v->latest == NULL)
        return 2;
    static char headers[16384];
    if (fetch_headers(v->latest, headers, sizeof headers) != 0)
        headers[0] = '\0';
    return gaudit_updates_latest_from(gaudit_pkg_backend_default(), v, headers, stdout);
}

/* --- Downloading a vendor package, on request ------------------------------ */

#define MAX_DOWNLOAD (1024LL * 1024 * 1024)

/* ~/.cache/gaudit/vendor, by the password database, made 0700 when missing;
 * whatever is in it removed. 0 on success. */
static int download_dir(char *dir, size_t len)
{
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/' || strlen(pw->pw_dir) + 32 > len)
        return -1;
    static const char *const parts[] = { "/.cache", "/.cache/gaudit", "/.cache/gaudit/vendor" };
    for (size_t i = 0; i < 3; i++) {
        snprintf(dir, len, "%s%s", pw->pw_dir, parts[i]);
        if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            return -1;
        struct stat st;
        if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid())
            return -1;
    }
    DIR *d = opendir(dir);
    if (d == NULL)
        return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            unlinkat(dirfd(d), de->d_name, 0);
    closedir(d);
    return 0;
}

int gaudit_updates_download(const char *id, const char *version)
{
    const gaudit_vendor_package *v = gaudit_vendor_find(id);
    /* Only what could be checked and installed: never for a vendor without a key. */
    if (v == NULL || v->prefix == NULL || v->key_file == NULL || !gaudit_vendor_plain_version(version))
        return 2;
    gaudit_update_download dl = { .status = 1 };
    snprintf(dl.id, sizeof dl.id, "%s", v->id);
    char dir[200], part[256], url[512];  /* the path must fit the line parser (256) */
    snprintf(url, sizeof url, "%s%s%s", v->prefix, version, v->suffix);
    const char *f = fetcher();
    if (f == NULL) {
        snprintf(dl.reason, sizeof dl.reason, "no-fetcher");
    } else if (download_dir(dir, sizeof dir) != 0
               || strlen(dir) + strlen(v->id) + sizeof "/.deb.part" > sizeof dl.path) {
        snprintf(dl.reason, sizeof dl.reason, "folder");
    } else {
        snprintf(part, sizeof part, "%s/%s.deb.part", dir, v->id);
        snprintf(dl.path, sizeof dl.path, "%s/%s.deb", dir, v->id);
        char *const wget[] = {
            (char *)WGET, (char *)"--no-config", (char *)"--quiet", (char *)"--https-only",
            (char *)"--max-redirect=0", (char *)"--tries=2", (char *)"--timeout=30",
            (char *)"--no-hsts", (char *)"--no-cookies", (char *)"-O", part, (char *)"--", url, NULL,
        };
        char *const curl[] = {
            (char *)CURL, (char *)"-q", (char *)"--silent", (char *)"--show-error", (char *)"--fail",
            (char *)"--proto", (char *)"=https", (char *)"--max-redirs", (char *)"0",
            (char *)"--max-filesize", (char *)"1073741824", (char *)"-o", part, (char *)"--", url, NULL,
        };
        char out[4096];
        struct stat st;
        int rc = run_fetcher(f == WGET ? wget : curl, out, sizeof out, 30 * 60 * 1000, part,
                             MAX_DOWNLOAD);
        if (rc == -2)
            snprintf(dl.reason, sizeof dl.reason, "size");
        else if (rc != 0)
            snprintf(dl.reason, sizeof dl.reason, "fetch-%d", rc);
        else if (lstat(part, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0
                 || st.st_size > MAX_DOWNLOAD)
            snprintf(dl.reason, sizeof dl.reason, "size");
        else if (rename(part, dl.path) != 0)
            snprintf(dl.reason, sizeof dl.reason, "rename");
        else
            dl.status = 0;
        if (dl.status != 0)
            unlink(part);
    }
    if (dl.status != 0)
        dl.path[0] = '\0';
    char buf[8192];
    if (gaudit_update_format_download(&dl, buf, sizeof buf) != 0 || fputs(buf, stdout) == EOF)
        return 1;
    return fflush(stdout) == 0 ? 0 : 1;
}

int gaudit_updates_mode(const char *level)
{
    if (level == NULL || strcmp(level, "quick") != 0)
        return 2;
    return gaudit_updates_collect(gaudit_pkg_backend_default(), gaudit_pkg_backend_expected(),
                                  (int64_t)time(NULL), stdout);
}
