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

static const gaudit_pkg_backend fake_pkg = {
    .name = "fake",
    .capability = fake_capability,
    .last_index_update = fake_index,
    .automatic_updates = fake_updates,
    .package_state = fake_packages,
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
        CHECK(r[k].verdict == GAUDIT_VERDICT_OK);
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
