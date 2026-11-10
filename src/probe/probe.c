/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/probe.h"

#include <stddef.h>
#include <stdio.h>

static const char *const probe_ids[GAUDIT_PROBE_COUNT] = {
    [GAUDIT_PROBE_PACKAGE_SYSTEM]       = "status.package-system",
    [GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS] = "status.other-package-systems",
    [GAUDIT_PROBE_ANTIVIRUS]            = "status.antivirus",
    [GAUDIT_PROBE_FIREWALL]             = "status.firewall",
    [GAUDIT_PROBE_AUTO_UPDATES]         = "status.auto-updates",
    [GAUDIT_PROBE_SECURITY_SOURCE]      = "status.security-source",
    [GAUDIT_PROBE_PACKAGE_INDEX]        = "status.package-index",
    [GAUDIT_PROBE_PENDING_UPGRADES]     = "status.pending-upgrades",
    [GAUDIT_PROBE_OBSOLETE_PACKAGES]    = "status.obsolete-packages",
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

/* A backend without the function, or one that says it is not implemented,
 * cannot check this here: "not supported", which is not the same as
 * "could not find out". */
static int unsupported(gaudit_backend_status status)
{
    return status == GAUDIT_BACKEND_NOT_IMPLEMENTED;
}

static void index_age(const gaudit_pkg_backend *pkg, int64_t now, gaudit_probe_result *r)
{
    int64_t epoch = 0;
    if (pkg->last_index_update == NULL) {
        r->unsupported = 1;
        return;
    }
    gaudit_backend_status status = pkg->last_index_update(&epoch);
    if (status != GAUDIT_BACKEND_OK) {
        r->unsupported = unsupported(status);
        return;
    }
    if (epoch > now)
        return;  /* from the future: clock or tampering, unknown */
    r->age_seconds = now - epoch;
    r->verdict = r->age_seconds > GAUDIT_PROBE_INDEX_MAX_AGE ? GAUDIT_VERDICT_WARNING
                                                             : GAUDIT_VERDICT_OK;
}

static void auto_updates(const gaudit_pkg_backend *pkg, gaudit_probe_result *r)
{
    int enabled = 0;
    if (pkg->automatic_updates == NULL) {
        r->unsupported = 1;
        return;
    }
    gaudit_backend_status status = pkg->automatic_updates(&enabled);
    if (status != GAUDIT_BACKEND_OK) {
        r->unsupported = unsupported(status);
        return;
    }
    r->verdict = enabled ? GAUDIT_VERDICT_OK : GAUDIT_VERDICT_WARNING;
}

/* A mirror may lag behind, and security updates must not wait for it. */
static void security_source(const gaudit_pkg_backend *pkg, gaudit_probe_result *r)
{
    if (pkg->security_sources == NULL) {
        r->applicable = 0;  /* no separate security source on this system */
        return;
    }
    unsigned official = 0, mirror = 0;
    gaudit_backend_status status =
        pkg->security_sources(&official, &mirror, r->text, sizeof r->text);
    if (status != GAUDIT_BACKEND_OK)
        return;  /* unknown */
    if (official == 0 && mirror == 0) {
        r->applicable = 0;  /* no security suite configured at all (e.g. Debian unstable) */
        return;
    }
    r->verdict = mirror > 0 ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
}

static void package_state(const gaudit_pkg_backend *pkg,
                          gaudit_probe_result *pending, gaudit_probe_result *obsolete)
{
    unsigned n_obsolete = 0, n_upgradable = 0;
    if (pkg->package_state == NULL) {
        pending->unsupported = obsolete->unsupported = 1;
        return;
    }
    gaudit_backend_status status = pkg->package_state(&n_obsolete, &n_upgradable);
    if (status != GAUDIT_BACKEND_OK) {
        pending->unsupported = obsolete->unsupported = unsupported(status);
        return;  /* both stay unknown */
    }
    pending->count = n_upgradable;
    pending->verdict = n_upgradable > 0 ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
    obsolete->count = n_obsolete;
    obsolete->verdict = n_obsolete > 0 ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
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

/* Package systems with installed packages that this backend does not check:
 * their packages are invisible to every other check, so say so. */
static void other_package_systems(const gaudit_pkg_backend *pkg, gaudit_probe_result *r)
{
    if (pkg->package_systems_present == NULL)
        return;  /* stays not applicable */
    unsigned mask = pkg->package_systems_present();
    if (pkg->own_package_system >= 0 && pkg->own_package_system < GAUDIT_PKGSYS_COUNT)
        mask &= ~(1u << pkg->own_package_system);
    if (mask == 0)
        return;
    r->applicable = 1;
    r->mask = mask;
    r->verdict = GAUDIT_VERDICT_WARNING;
}

void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    gaudit_probe_collect_ex(pkg, NULL, now, out);
}

void gaudit_probe_collect_ex(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                             int64_t now, gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        out[k].kind = (gaudit_probe_kind)k;
        out[k].id = gaudit_probe_id((gaudit_probe_kind)k);
        out[k].verdict = GAUDIT_VERDICT_UNKNOWN;
        out[k].age_seconds = 0;
        out[k].count = 0;
        out[k].extra_count = 0;
        out[k].info_count = 0;
        out[k].applicable = 1;
        out[k].missing_capability[0] = '\0';
        out[k].unsupported = 0;
        out[k].detail[0] = '\0';
        out[k].mask = 0;
        out[k].until_epoch = 0;
        out[k].service_down = 0;
        out[k].text[0] = '\0';
    }
    out[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].applicable = 0;
    out[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable = 0;
    if (expected != NULL && expected != pkg) {
        gaudit_probe_result *r = &out[GAUDIT_PROBE_PACKAGE_SYSTEM];
        r->applicable = 1;
        r->verdict = GAUDIT_VERDICT_WARNING;
        snprintf(r->detail, sizeof r->detail, "%s",
                 expected->package_system != NULL ? expected->package_system : "");
    }

    if (pkg == NULL)
        return;

    out[GAUDIT_PROBE_ANTIVIRUS].verdict = any_present(pkg, antivirus_caps);
    out[GAUDIT_PROBE_FIREWALL].verdict = any_present(pkg, firewall_caps);
    index_age(pkg, now, &out[GAUDIT_PROBE_PACKAGE_INDEX]);
    auto_updates(pkg, &out[GAUDIT_PROBE_AUTO_UPDATES]);
    security_source(pkg, &out[GAUDIT_PROBE_SECURITY_SOURCE]);
    package_state(pkg, &out[GAUDIT_PROBE_PENDING_UPGRADES],
                  &out[GAUDIT_PROBE_OBSOLETE_PACKAGES]);
    flatpak(pkg, &out[GAUDIT_PROBE_FLATPAK]);
    snap(pkg, now, &out[GAUDIT_PROBE_SNAP]);
    other_package_systems(pkg, &out[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS]);
}
