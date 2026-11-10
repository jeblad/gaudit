/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/probe.h"

#include <stddef.h>

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

static gaudit_verdict index_age(const gaudit_pkg_backend *pkg, int64_t now, int64_t *age)
{
    int64_t epoch = 0;
    *age = 0;
    if (pkg->last_index_update == NULL
        || pkg->last_index_update(&epoch) != GAUDIT_BACKEND_OK)
        return GAUDIT_VERDICT_UNKNOWN;
    if (epoch > now)
        return GAUDIT_VERDICT_UNKNOWN;  /* from the future: clock or tampering */
    *age = now - epoch;
    return *age > GAUDIT_PROBE_INDEX_MAX_AGE ? GAUDIT_VERDICT_WARNING : GAUDIT_VERDICT_OK;
}

static gaudit_verdict auto_updates(const gaudit_pkg_backend *pkg)
{
    int enabled = 0;
    if (pkg->automatic_updates == NULL
        || pkg->automatic_updates(&enabled) != GAUDIT_BACKEND_OK)
        return GAUDIT_VERDICT_UNKNOWN;
    return enabled ? GAUDIT_VERDICT_OK : GAUDIT_VERDICT_WARNING;
}

static void package_state(const gaudit_pkg_backend *pkg,
                          gaudit_probe_result *pending, gaudit_probe_result *obsolete)
{
    unsigned n_obsolete = 0, n_upgradable = 0;
    if (pkg->package_state == NULL
        || pkg->package_state(&n_obsolete, &n_upgradable) != GAUDIT_BACKEND_OK)
        return;  /* both stay unknown */
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
        r->missing_capability = "libflatpak";
        break;
    case GAUDIT_BACKEND_ERROR:
    default:
        break;  /* unknown */
    }
}

void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        out[k].kind = (gaudit_probe_kind)k;
        out[k].verdict = GAUDIT_VERDICT_UNKNOWN;
        out[k].age_seconds = 0;
        out[k].count = 0;
        out[k].extra_count = 0;
        out[k].info_count = 0;
        out[k].applicable = 1;
        out[k].missing_capability = NULL;
    }
    out[GAUDIT_PROBE_ANTIVIRUS].id = "status.antivirus";
    out[GAUDIT_PROBE_FIREWALL].id = "status.firewall";
    out[GAUDIT_PROBE_AUTO_UPDATES].id = "status.auto-updates";
    out[GAUDIT_PROBE_PACKAGE_INDEX].id = "status.package-index";
    out[GAUDIT_PROBE_PENDING_UPGRADES].id = "status.pending-upgrades";
    out[GAUDIT_PROBE_OBSOLETE_PACKAGES].id = "status.obsolete-packages";
    out[GAUDIT_PROBE_FLATPAK].id = "status.flatpak";

    if (pkg == NULL)
        return;

    out[GAUDIT_PROBE_ANTIVIRUS].verdict = any_present(pkg, antivirus_caps);
    out[GAUDIT_PROBE_FIREWALL].verdict = any_present(pkg, firewall_caps);
    out[GAUDIT_PROBE_PACKAGE_INDEX].verdict =
        index_age(pkg, now, &out[GAUDIT_PROBE_PACKAGE_INDEX].age_seconds);
    out[GAUDIT_PROBE_AUTO_UPDATES].verdict = auto_updates(pkg);
    package_state(pkg, &out[GAUDIT_PROBE_PENDING_UPGRADES],
                  &out[GAUDIT_PROBE_OBSOLETE_PACKAGES]);
    flatpak(pkg, &out[GAUDIT_PROBE_FLATPAK]);
}
