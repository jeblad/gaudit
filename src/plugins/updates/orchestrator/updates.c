/* SPDX-License-Identifier: GPL-3.0-only */
/* Facts only: how often updates are looked for, whether they are installed
 * automatically, what waits, where security updates come from, what no
 * source keeps up to date. Read directly by the backend, never through
 * an admin tool; the rule decides what is a warning. */
#include "updates-mode.h"
#include "updates.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

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

static void count_group(const char *name, const char *arch, const char *version,
                        gaudit_sourceless_group group, const char *offered, void *ctx)
{
    (void)name; (void)arch; (void)version; (void)offered;
    unsigned *groups = ctx;
    if (group >= 0 && group < GAUDIT_SOURCELESS_GROUPS)
        groups[group]++;
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
    gaudit_update_settings set = { -1, -1, -1, -1, -1, -1, -1, -1, "", -1, -1 };
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
    put(&s, GAUDIT_UPDATE_SOURCELESS, counts, obsolete, NULL);

    unsigned groups[GAUDIT_SOURCELESS_GROUPS] = { 0 };
    gaudit_backend_status gst = pkg->sourceless_packages != NULL
        ? pkg->sourceless_packages(count_group, groups) : GAUDIT_BACKEND_NOT_IMPLEMENTED;
    gaudit_fact_status gstatus = from_backend(gst);
    /* The groups must add up to the count, or none of them is trusted. */
    if (gst == GAUDIT_BACKEND_OK && counts == GAUDIT_FACT_KNOWN
        && groups[0] + groups[1] + groups[2] != obsolete)
        gstatus = GAUDIT_FACT_UNKNOWN;
    put(&s, GAUDIT_UPDATE_SOURCELESS_ABOVE, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[0] : 0, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_LEFTOVER, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[1] : 0, NULL);
    put(&s, GAUDIT_UPDATE_SOURCELESS_OTHER, gstatus, gstatus == GAUDIT_FACT_KNOWN ? groups[2] : 0, NULL);

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

    char line[64];
    if (s.failed || gaudit_update_format_end(s.written, line, sizeof line) != 0
        || fputs(line, out) == EOF)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

int gaudit_updates_mode(const char *level)
{
    if (level == NULL || strcmp(level, "quick") != 0)
        return 2;
    return gaudit_updates_collect(gaudit_pkg_backend_default(), gaudit_pkg_backend_expected(),
                                  (int64_t)time(NULL), stdout);
}
