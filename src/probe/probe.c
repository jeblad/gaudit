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

void gaudit_probe_collect(const gaudit_pkg_backend *pkg, int64_t now,
                          gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        out[k].kind = (gaudit_probe_kind)k;
        out[k].verdict = GAUDIT_VERDICT_UNKNOWN;
        out[k].age_seconds = 0;
        out[k].count = 0;
    }
    out[GAUDIT_PROBE_ANTIVIRUS].id = "status.antivirus";
    out[GAUDIT_PROBE_FIREWALL].id = "status.firewall";
    out[GAUDIT_PROBE_AUTO_UPDATES].id = "status.auto-updates";
    out[GAUDIT_PROBE_PACKAGE_INDEX].id = "status.package-index";
    out[GAUDIT_PROBE_PENDING_UPGRADES].id = "status.pending-upgrades";
    out[GAUDIT_PROBE_OBSOLETE_PACKAGES].id = "status.obsolete-packages";

    if (pkg == NULL)
        return;

    out[GAUDIT_PROBE_ANTIVIRUS].verdict = any_present(pkg, antivirus_caps);
    out[GAUDIT_PROBE_FIREWALL].verdict = any_present(pkg, firewall_caps);
    out[GAUDIT_PROBE_PACKAGE_INDEX].verdict =
        index_age(pkg, now, &out[GAUDIT_PROBE_PACKAGE_INDEX].age_seconds);
    out[GAUDIT_PROBE_AUTO_UPDATES].verdict = auto_updates(pkg);
    package_state(pkg, &out[GAUDIT_PROBE_PENDING_UPGRADES],
                  &out[GAUDIT_PROBE_OBSOLETE_PACKAGES]);
}
