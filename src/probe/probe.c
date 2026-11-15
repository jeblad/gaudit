/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/probe.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const char *const probe_ids[GAUDIT_PROBE_COUNT] = {
    [GAUDIT_PROBE_ANTIVIRUS]            = "status.antivirus",
    [GAUDIT_PROBE_FIREWALL]             = "status.firewall",
    [GAUDIT_PROBE_LISTENING]            = "status.listening",
    [GAUDIT_PROBE_FLATPAK]              = "status.flatpak",
    [GAUDIT_PROBE_SNAP]                 = "status.snap",
};

const char *gaudit_probe_id(gaudit_probe_kind kind)
{
    return kind >= 0 && kind < GAUDIT_PROBE_COUNT ? probe_ids[kind] : NULL;
}

/* Capabilities per category, in distro-neutral terms. */
static const char *const antivirus_caps[] = { "clamav", NULL };
static const char *const firewall_caps[]  = { "ufw", "firewalld", NULL };

static gaudit_verdict any_present(const gaudit_pkg_backend *pkg, const char *const *ids)
{
    for (const char *const *id = ids; *id != NULL; id++)
        if (pkg->capability != NULL && gaudit_capability_present(pkg->capability(*id)))
            return GAUDIT_VERDICT_OK;
    return GAUDIT_VERDICT_WARNING;
}

/* Informs only: without root, Home cannot tell whether a firewall stands
 * in front of these services (the firewall check on page 2 can). */
static void listening(const gaudit_pkg_backend *pkg, gaudit_probe_result *r)
{
    if (pkg->listening == NULL) {
        r->applicable = 0;
        return;
    }
    unsigned services = 0, own = 0;
    if (pkg->listening(&services, &own) != GAUDIT_BACKEND_OK)
        return;
    r->count = services;
    r->extra_count = own;
    r->verdict = GAUDIT_VERDICT_OK;
}

static void flatpak(const gaudit_pkg_backend *pkg, gaudit_probe_result *r)
{
    if (pkg->flatpak_state == NULL) {
        r->applicable = 0;
        return;
    }
    gaudit_flatpak_state st = { 0 };
    switch (pkg->flatpak_state(&st)) {
    case GAUDIT_BACKEND_OK:
        r->count = st.eol_apps;
        r->extra_count = st.eol_unused;
        r->info_count = st.eol_pinned;
        r->verdict = st.eol_apps > 0 || st.eol_unused > 0 || st.eol_pinned > 0
                         ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
        break;
    case GAUDIT_BACKEND_UNAVAILABLE:      /* Flatpak not in use */
    case GAUDIT_BACKEND_NOT_IMPLEMENTED:  /* built without the collector */
        r->applicable = 0;
        break;
    case GAUDIT_BACKEND_MISSING_DEPENDENCY:
        snprintf(r->missing_capability, sizeof r->missing_capability, "libflatpak");
        break;
    case GAUDIT_BACKEND_ERROR:
    default:
        break;  /* unknown */
    }
}

static void snap(const gaudit_pkg_backend *pkg, int64_t now, gaudit_probe_result *r)
{
    if (pkg->snap_state == NULL) {
        r->applicable = 0;
        return;
    }
    gaudit_snap_state st = { 0 };
    switch (pkg->snap_state(&st)) {
    case GAUDIT_BACKEND_OK:
        break;
    case GAUDIT_BACKEND_UNAVAILABLE:      /* Snap not in use */
    case GAUDIT_BACKEND_NOT_IMPLEMENTED:  /* built without the collector */
        r->applicable = 0;
        return;
    case GAUDIT_BACKEND_MISSING_DEPENDENCY:
        snprintf(r->missing_capability, sizeof r->missing_capability, "libjson-glib");
        return;
    case GAUDIT_BACKEND_ERROR:
    default:
        return;  /* unknown */
    }

    if (!st.running) {
        /* Installed, but nothing keeps the snaps up to date. */
        r->service_down = 1;
        r->verdict = GAUDIT_VERDICT_WARNING;
        return;
    }
    r->count = st.devmode;
    r->extra_count = st.held;
    r->info_count = st.classic;  /* reviewed and chosen on install: informs only */
    r->until_epoch = st.refresh_hold > now ? st.refresh_hold : 0;
    r->age_seconds = st.last_refresh > 0 && st.last_refresh <= now ? now - st.last_refresh : -1;

    int stale = r->age_seconds > GAUDIT_PROBE_SNAP_MAX_AGE;
    r->verdict = st.devmode > 0 || st.held > 0 || r->until_epoch > 0 || stale
                     ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
}

void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    gaudit_probe_collect_ex(pkg, NULL, now, out);
}

void gaudit_probe_init(gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        memset(&out[k], 0, sizeof out[k]);
        out[k].kind = (gaudit_probe_kind)k;
        out[k].id = gaudit_probe_id((gaudit_probe_kind)k);
        out[k].verdict = GAUDIT_VERDICT_UNKNOWN;
        out[k].applicable = 1;
    }
}

#define BIT(k) (1u << (k))

/* Each task fills the kinds it lists. */
static const unsigned task_kinds[GAUDIT_PROBE_TASK_COUNT] = {
    BIT(GAUDIT_PROBE_ANTIVIRUS) | BIT(GAUDIT_PROBE_FIREWALL),
    BIT(GAUDIT_PROBE_FLATPAK),
    BIT(GAUDIT_PROBE_SNAP),
    BIT(GAUDIT_PROBE_LISTENING),
};

unsigned gaudit_probe_task_kinds(int task)
{
    return task >= 0 && task < GAUDIT_PROBE_TASK_COUNT ? task_kinds[task] : 0;
}

void gaudit_probe_run_task(int task, const gaudit_pkg_backend *pkg,
                           const gaudit_pkg_backend *expected, int64_t now,
                           gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    (void)expected;
    if (pkg == NULL)
        return;
    switch (task) {
    case 0:
        out[GAUDIT_PROBE_ANTIVIRUS].verdict = any_present(pkg, antivirus_caps);
        out[GAUDIT_PROBE_FIREWALL].verdict = any_present(pkg, firewall_caps);
        break;
    case 1:
        flatpak(pkg, &out[GAUDIT_PROBE_FLATPAK]);
        break;
    case 2:
        snap(pkg, now, &out[GAUDIT_PROBE_SNAP]);
        break;
    case 3:
        listening(pkg, &out[GAUDIT_PROBE_LISTENING]);
        break;
    default:
        break;
    }
}

void gaudit_probe_collect_ex(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                             int64_t now, gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    gaudit_probe_init(out);
    for (int t = 0; t < GAUDIT_PROBE_TASK_COUNT; t++)
        gaudit_probe_run_task(t, pkg, expected, now, out);
}
