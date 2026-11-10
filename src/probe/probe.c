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
        out[k].unsupported = 0;
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
    index_age(pkg, now, &out[GAUDIT_PROBE_PACKAGE_INDEX]);
    auto_updates(pkg, &out[GAUDIT_PROBE_AUTO_UPDATES]);
    package_state(pkg, &out[GAUDIT_PROBE_PENDING_UPGRADES],
                  &out[GAUDIT_PROBE_OBSOLETE_PACKAGES]);
    flatpak(pkg, &out[GAUDIT_PROBE_FLATPAK]);
}
