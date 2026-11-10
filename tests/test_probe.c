/* SPDX-License-Identifier: GPL-3.0-only */
/* Status probe verdicts, driven by a fake backend. */
#include "gaudit/probe.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define NOW ((int64_t)1800000000)
#define DAY ((int64_t)24 * 60 * 60)

/* --- Fake backend --------------------------------------------------------- */

static const char *const present_paths[] = { "/bin/sh", NULL };
static const char *const absent_paths[]  = { "/nonexistent/gaudit-test", NULL };
static const char *const no_packages[]   = { NULL };

static const gaudit_capability cap_present = { "present", present_paths, no_packages };
static const gaudit_capability cap_absent  = { "absent",  absent_paths,  no_packages };

static struct {
    int antivirus;
    int firewall;
    gaudit_backend_status index_status;
    int64_t index_epoch;
    gaudit_backend_status updates_status;
    int updates_enabled;
    gaudit_backend_status packages_status;
    unsigned obsolete;
    unsigned upgradable;
    gaudit_backend_status flatpak_status;
    gaudit_flatpak_state flatpak;
} fake;

static const gaudit_capability *fake_capability(const char *id)
{
    if (strcmp(id, "clamav") == 0)
        return fake.antivirus ? &cap_present : &cap_absent;
    if (strcmp(id, "ufw") == 0)
        return fake.firewall ? &cap_present : &cap_absent;
    return NULL;  /* e.g. firewalld: unknown on this fake distro */
}

static gaudit_backend_status fake_index(int64_t *out_epoch)
{
    *out_epoch = fake.index_epoch;
    return fake.index_status;
}

static gaudit_backend_status fake_updates(int *out_enabled)
{
    *out_enabled = fake.updates_enabled;
    return fake.updates_status;
}

static gaudit_backend_status fake_packages(unsigned *out_obsolete, unsigned *out_upgradable)
{
    *out_obsolete = fake.obsolete;
    *out_upgradable = fake.upgradable;
    return fake.packages_status;
}

static gaudit_backend_status fake_flatpak(gaudit_flatpak_state *out)
{
    *out = fake.flatpak;
    return fake.flatpak_status;
}

static gaudit_backend_status fake_snap_status;
static gaudit_snap_state fake_snap_st;

static gaudit_backend_status fake_snap(gaudit_snap_state *out)
{
    *out = fake_snap_st;
    return fake_snap_status;
}

static gaudit_backend_status fake_sec_status;
static unsigned fake_sec_official, fake_sec_mirror;

static gaudit_backend_status fake_security(unsigned *official, unsigned *mirror,
                                           char *host, size_t len)
{
    *official = fake_sec_official;
    *mirror = fake_sec_mirror;
    snprintf(host, len, "%s", fake_sec_mirror ? "mirror.example.org" : "");
    return fake_sec_status;
}

static unsigned fake_present_mask;

static unsigned fake_present(void)
{
    return fake_present_mask;
}

static const gaudit_pkg_backend fake_pkg = {
    .name = "fake",
    .capability = fake_capability,
    .last_index_update = fake_index,
    .automatic_updates = fake_updates,
    .package_state = fake_packages,
    .flatpak_state = fake_flatpak,
};

static void all_good(void)
{
    fake.antivirus = 1;
    fake.firewall = 1;
    fake.index_status = GAUDIT_BACKEND_OK;
    fake.index_epoch = NOW - DAY / 2;
    fake.updates_status = GAUDIT_BACKEND_OK;
    fake.updates_enabled = 1;
    fake.packages_status = GAUDIT_BACKEND_OK;
    fake.obsolete = 0;
    fake.upgradable = 0;
    fake.flatpak_status = GAUDIT_BACKEND_OK;
    fake.flatpak = (gaudit_flatpak_state){ .apps = 5 };
}

static gaudit_verdict run(gaudit_probe_kind kind)
{
    gaudit_probe_result r[GAUDIT_PROBE_COUNT];
    gaudit_probe_collect(&fake_pkg, NOW, r);
    return r[kind].verdict;
}

/* --- Tests ---------------------------------------------------------------- */

int main(void)
{
    gaudit_probe_result r[GAUDIT_PROBE_COUNT];

    all_good();
    gaudit_probe_collect(&fake_pkg, NOW, r);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        CHECK(r[k].kind == (gaudit_probe_kind)k);
        CHECK(r[k].id != NULL && strncmp(r[k].id, "status.", 7) == 0);
        CHECK(!r[k].applicable || r[k].verdict == GAUDIT_VERDICT_OK);
    }
    CHECK(r[GAUDIT_PROBE_PACKAGE_INDEX].age_seconds == DAY / 2);

    /* Missing programs. */
    all_good(); fake.antivirus = 0;
    CHECK(run(GAUDIT_PROBE_ANTIVIRUS) == GAUDIT_VERDICT_WARNING);
    all_good(); fake.firewall = 0;
    CHECK(run(GAUDIT_PROBE_FIREWALL) == GAUDIT_VERDICT_WARNING);

    /* Package index age, including the boundary. */
    all_good(); fake.index_epoch = NOW - GAUDIT_PROBE_INDEX_MAX_AGE;
    CHECK(run(GAUDIT_PROBE_PACKAGE_INDEX) == GAUDIT_VERDICT_OK);
    all_good(); fake.index_epoch = NOW - GAUDIT_PROBE_INDEX_MAX_AGE - 1;
    CHECK(run(GAUDIT_PROBE_PACKAGE_INDEX) == GAUDIT_VERDICT_WARNING);
    all_good(); fake.index_epoch = NOW + DAY;   /* from the future */
    CHECK(run(GAUDIT_PROBE_PACKAGE_INDEX) == GAUDIT_VERDICT_UNKNOWN);
    all_good(); fake.index_status = GAUDIT_BACKEND_UNAVAILABLE;
    CHECK(run(GAUDIT_PROBE_PACKAGE_INDEX) == GAUDIT_VERDICT_UNKNOWN);

    /* Automatic updates. */
    all_good(); fake.updates_enabled = 0;
    CHECK(run(GAUDIT_PROBE_AUTO_UPDATES) == GAUDIT_VERDICT_WARNING);
    all_good(); fake.updates_status = GAUDIT_BACKEND_ERROR;
    CHECK(run(GAUDIT_PROBE_AUTO_UPDATES) == GAUDIT_VERDICT_UNKNOWN);

    /* Package state: counts carried through, both rows from one scan. */
    all_good(); fake.upgradable = 3; fake.obsolete = 2;
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].count == 3);
    CHECK(r[GAUDIT_PROBE_OBSOLETE_PACKAGES].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_OBSOLETE_PACKAGES].count == 2);
    all_good(); fake.packages_status = GAUDIT_BACKEND_UNAVAILABLE;
    CHECK(run(GAUDIT_PROBE_PENDING_UPGRADES) == GAUDIT_VERDICT_UNKNOWN);
    CHECK(run(GAUDIT_PROBE_OBSOLETE_PACKAGES) == GAUDIT_VERDICT_UNKNOWN);

    /* Flatpak: counts, and when the row does not apply. */
    all_good(); fake.flatpak.eol_apps = 2; fake.flatpak.eol_unused = 3;
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_FLATPAK].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_FLATPAK].count == 2 && r[GAUDIT_PROBE_FLATPAK].extra_count == 3);
    CHECK(r[GAUDIT_PROBE_FLATPAK].applicable && r[GAUDIT_PROBE_FLATPAK].missing_capability == NULL);
    all_good(); fake.flatpak.eol_pinned = 2;  /* kept but unused: also a warning */
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_FLATPAK].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_FLATPAK].info_count == 2);
    all_good(); fake.flatpak_status = GAUDIT_BACKEND_UNAVAILABLE;      /* no Flatpak */
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(!r[GAUDIT_PROBE_FLATPAK].applicable);
    all_good(); fake.flatpak_status = GAUDIT_BACKEND_NOT_IMPLEMENTED;  /* built without it */
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(!r[GAUDIT_PROBE_FLATPAK].applicable);
    all_good(); fake.flatpak_status = GAUDIT_BACKEND_MISSING_DEPENDENCY;
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_FLATPAK].applicable);
    CHECK(r[GAUDIT_PROBE_FLATPAK].verdict == GAUDIT_VERDICT_UNKNOWN);
    CHECK(r[GAUDIT_PROBE_FLATPAK].missing_capability != NULL
          && strcmp(r[GAUDIT_PROBE_FLATPAK].missing_capability, "libflatpak") == 0);
    all_good(); fake.flatpak_status = GAUDIT_BACKEND_ERROR;
    CHECK(run(GAUDIT_PROBE_FLATPAK) == GAUDIT_VERDICT_UNKNOWN);

    /* A backend without package functions (e.g. the generic one), or one
     * that says "not implemented": not supported, which is not unknown. */
    static const gaudit_pkg_backend bare_pkg = { .name = "bare", .capability = fake_capability };
    all_good();
    gaudit_probe_collect(&bare_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_AUTO_UPDATES].unsupported);
    CHECK(r[GAUDIT_PROBE_PACKAGE_INDEX].unsupported);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].unsupported);
    CHECK(r[GAUDIT_PROBE_OBSOLETE_PACKAGES].unsupported);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].verdict == GAUDIT_VERDICT_UNKNOWN);
    CHECK(!r[GAUDIT_PROBE_ANTIVIRUS].unsupported && r[GAUDIT_PROBE_ANTIVIRUS].verdict == GAUDIT_VERDICT_OK);
    CHECK(!r[GAUDIT_PROBE_FLATPAK].applicable);
    all_good(); fake.packages_status = GAUDIT_BACKEND_NOT_IMPLEMENTED;
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].unsupported && r[GAUDIT_PROBE_OBSOLETE_PACKAGES].unsupported);
    all_good(); fake.packages_status = GAUDIT_BACKEND_ERROR;  /* could not tell: unknown, not unsupported */
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(!r[GAUDIT_PROBE_PENDING_UPGRADES].unsupported);
    CHECK(r[GAUDIT_PROBE_PENDING_UPGRADES].verdict == GAUDIT_VERDICT_UNKNOWN);

    /* Source of security updates. */
    {
        static const gaudit_pkg_backend sec_pkg = { .name = "sec", .capability = fake_capability,
                                                    .security_sources = fake_security };
        fake_sec_status = GAUDIT_BACKEND_OK;
        fake_sec_official = 1; fake_sec_mirror = 0;
        gaudit_probe_collect(&sec_pkg, NOW, r);
        CHECK(r[GAUDIT_PROBE_SECURITY_SOURCE].applicable);
        CHECK(r[GAUDIT_PROBE_SECURITY_SOURCE].verdict == GAUDIT_VERDICT_OK);
        fake_sec_official = 0; fake_sec_mirror = 1;
        gaudit_probe_collect(&sec_pkg, NOW, r);
        CHECK(r[GAUDIT_PROBE_SECURITY_SOURCE].verdict == GAUDIT_VERDICT_WARNING);
        CHECK(strcmp(r[GAUDIT_PROBE_SECURITY_SOURCE].text, "mirror.example.org") == 0);
        fake_sec_official = 1; fake_sec_mirror = 1;  /* one mirror is enough to warn */
        gaudit_probe_collect(&sec_pkg, NOW, r);
        CHECK(r[GAUDIT_PROBE_SECURITY_SOURCE].verdict == GAUDIT_VERDICT_WARNING);
        fake_sec_official = 0; fake_sec_mirror = 0;  /* no security suite */
        gaudit_probe_collect(&sec_pkg, NOW, r);
        CHECK(!r[GAUDIT_PROBE_SECURITY_SOURCE].applicable);
        fake_sec_status = GAUDIT_BACKEND_ERROR;
        gaudit_probe_collect(&sec_pkg, NOW, r);
        CHECK(r[GAUDIT_PROBE_SECURITY_SOURCE].verdict == GAUDIT_VERDICT_UNKNOWN);
        gaudit_probe_collect(&fake_pkg, NOW, r);  /* backend without the function */
        CHECK(!r[GAUDIT_PROBE_SECURITY_SOURCE].applicable);
    }

    /* Snap. */
    static const gaudit_pkg_backend snap_pkg = { .name = "snap", .capability = fake_capability,
                                                 .snap_state = fake_snap };
    const gaudit_snap_state fresh = { .running = 1, .snaps = 10, .last_refresh = NOW - DAY };
#define SNAP_RUN(state, status) (fake_snap_st = (state), fake_snap_status = (status), \
                                 gaudit_probe_collect(&snap_pkg, NOW, r), r[GAUDIT_PROBE_SNAP])
    {
        gaudit_snap_state s = fresh;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_OK);
        s.classic = 2;  /* informs only */
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_OK);
        CHECK(r[GAUDIT_PROBE_SNAP].info_count == 2);
        s = fresh; s.devmode = 1;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_WARNING);
        s = fresh; s.held = 1;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_WARNING);
        s = fresh; s.refresh_hold = NOW + DAY;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_WARNING);
        CHECK(r[GAUDIT_PROBE_SNAP].until_epoch == NOW + DAY);
        s = fresh; s.refresh_hold = NOW - DAY;  /* hold already over */
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_OK);
        s = fresh; s.last_refresh = NOW - GAUDIT_PROBE_SNAP_MAX_AGE - 1;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_WARNING);
        s = fresh; s.last_refresh = 0;  /* unknown time alone is no finding */
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_OK);
        s = fresh; s.running = 0;
        CHECK(SNAP_RUN(s, GAUDIT_BACKEND_OK).verdict == GAUDIT_VERDICT_WARNING);
        CHECK(r[GAUDIT_PROBE_SNAP].service_down);
        CHECK(!SNAP_RUN(fresh, GAUDIT_BACKEND_UNAVAILABLE).applicable);
        CHECK(!SNAP_RUN(fresh, GAUDIT_BACKEND_NOT_IMPLEMENTED).applicable);
        CHECK(SNAP_RUN(fresh, GAUDIT_BACKEND_MISSING_DEPENDENCY).missing_capability != NULL);
        CHECK(SNAP_RUN(fresh, GAUDIT_BACKEND_ERROR).verdict == GAUDIT_VERDICT_UNKNOWN);
    }
#undef SNAP_RUN

    /* Package systems this backend does not check. */
    static const gaudit_pkg_backend deb_like = {
        .name = "deb-like", .capability = fake_capability,
        .own_package_system = GAUDIT_PKGSYS_DPKG, .package_systems_present = fake_present,
    };
    static const gaudit_pkg_backend generic_like = {
        .name = "generic-like", .capability = fake_capability,
        .own_package_system = -1, .package_systems_present = fake_present,
    };
    fake_present_mask = 1u << GAUDIT_PKGSYS_DPKG;                    /* only its own */
    gaudit_probe_collect(&deb_like, NOW, r);
    CHECK(!r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].applicable);
    fake_present_mask = (1u << GAUDIT_PKGSYS_DPKG) | (1u << GAUDIT_PKGSYS_RPM) | (1u << GAUDIT_PKGSYS_NIX);
    gaudit_probe_collect(&deb_like, NOW, r);
    CHECK(r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].applicable);
    CHECK(r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].mask
          == ((1u << GAUDIT_PKGSYS_RPM) | (1u << GAUDIT_PKGSYS_NIX)));
    fake_present_mask = 1u << GAUDIT_PKGSYS_PORTAGE;                 /* Gentoo, no backend */
    gaudit_probe_collect(&generic_like, NOW, r);
    CHECK(r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].applicable);
    CHECK(r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].mask == 1u << GAUDIT_PKGSYS_PORTAGE);
    fake_present_mask = 0;
    gaudit_probe_collect(&generic_like, NOW, r);
    CHECK(!r[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].applicable);

    /* Expectation from the distribution vs what was detected. */
    static const gaudit_pkg_backend expected_pkg = { .name = "expected", .package_system = "dpkg/apt" };
    all_good();
    gaudit_probe_collect_ex(&fake_pkg, &expected_pkg, NOW, r);  /* expected one not found */
    CHECK(r[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable);
    CHECK(r[GAUDIT_PROBE_PACKAGE_SYSTEM].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_PACKAGE_SYSTEM].detail != NULL
          && strcmp(r[GAUDIT_PROBE_PACKAGE_SYSTEM].detail, "dpkg/apt") == 0);
    gaudit_probe_collect_ex(&fake_pkg, &fake_pkg, NOW, r);      /* as expected */
    CHECK(!r[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable);
    gaudit_probe_collect_ex(&fake_pkg, NULL, NOW, r);           /* no expectation */
    CHECK(!r[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable);
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(!r[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable);

    /* No backend: everything unknown, ids still set. */
    gaudit_probe_collect(NULL, NOW, r);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        CHECK(r[k].verdict == GAUDIT_VERDICT_UNKNOWN);
        CHECK(r[k].id != NULL);
    }

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
