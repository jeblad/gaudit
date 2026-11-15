/* SPDX-License-Identifier: GPL-3.0-only */
/* Status probe verdicts, driven by a fake backend. The update rows are
 * the Updates plugin's now (tests/test_updates.c and the engine test). */
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

static const gaudit_pkg_backend fake_pkg = {
    .name = "fake",
    .capability = fake_capability,
    .flatpak_state = fake_flatpak,
};

static void all_good(void)
{
    fake.antivirus = 1;
    fake.firewall = 1;
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

    /* Missing programs. */
    all_good(); fake.antivirus = 0;
    CHECK(run(GAUDIT_PROBE_ANTIVIRUS) == GAUDIT_VERDICT_WARNING);
    all_good(); fake.firewall = 0;
    CHECK(run(GAUDIT_PROBE_FIREWALL) == GAUDIT_VERDICT_WARNING);

    /* Flatpak: counts, and when the row does not apply. */
    all_good(); fake.flatpak.eol_apps = 2; fake.flatpak.eol_unused = 3;
    gaudit_probe_collect(&fake_pkg, NOW, r);
    CHECK(r[GAUDIT_PROBE_FLATPAK].verdict == GAUDIT_VERDICT_WARNING);
    CHECK(r[GAUDIT_PROBE_FLATPAK].count == 2 && r[GAUDIT_PROBE_FLATPAK].extra_count == 3);
    CHECK(r[GAUDIT_PROBE_FLATPAK].applicable && r[GAUDIT_PROBE_FLATPAK].missing_capability[0] == '\0');
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
    CHECK(strcmp(r[GAUDIT_PROBE_FLATPAK].missing_capability, "libflatpak") == 0);
    all_good(); fake.flatpak_status = GAUDIT_BACKEND_ERROR;
    CHECK(run(GAUDIT_PROBE_FLATPAK) == GAUDIT_VERDICT_UNKNOWN);

    /* A backend without the functions (e.g. the generic one). */
    static const gaudit_pkg_backend bare_pkg = { .name = "bare", .capability = fake_capability };
    all_good();
    gaudit_probe_collect(&bare_pkg, NOW, r);
    CHECK(!r[GAUDIT_PROBE_ANTIVIRUS].unsupported && r[GAUDIT_PROBE_ANTIVIRUS].verdict == GAUDIT_VERDICT_OK);
    CHECK(!r[GAUDIT_PROBE_FLATPAK].applicable);

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
        CHECK(SNAP_RUN(fresh, GAUDIT_BACKEND_MISSING_DEPENDENCY).missing_capability[0] != '\0');
        CHECK(SNAP_RUN(fresh, GAUDIT_BACKEND_ERROR).verdict == GAUDIT_VERDICT_UNKNOWN);
    }
#undef SNAP_RUN

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
