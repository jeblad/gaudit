/* SPDX-License-Identifier: GPL-3.0-only */
/* dpkg version ordering and the installed-vs-available scan on fixtures in
 * tests/data/dpkg/. */
#include "dpkg.h"

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

#define LESS(a, b)  CHECK(gaudit_deb_version_compare(a, b) < 0 && gaudit_deb_version_compare(b, a) > 0)
#define EQUAL(a, b) CHECK(gaudit_deb_version_compare(a, b) == 0)

#define DATA GAUDIT_TEST_DATA_DIR "/dpkg"

static void count_reported(const char *name, const char *arch, const char *version, void *ctx)
{
    (void)arch;
    (void)version;
    CHECK(strcmp(name, "c") == 0 || strcmp(name, "h") == 0 || strcmp(name, "thunderbird") == 0);
    (*(unsigned *)ctx)++;
}

int main(void)
{
    /* Version ordering, as dpkg --compare-versions. */
    EQUAL("1.0-1", "1.0-1");
    EQUAL("0:1.0", "1.0");
    EQUAL("1.0", "1.00");
    LESS("1.0", "1.0-1");          /* missing revision sorts first */
    LESS("1.0~rc1", "1.0");        /* tilde sorts before everything */
    LESS("1.0~~", "1.0~");
    LESS("1.0", "1.0a");
    LESS("1.0", "1.0+dfsg");
    LESS("1.9", "1.10");
    LESS("2.0", "1:0.9");          /* epoch wins */
    LESS("2.30-2ubuntu1", "2.30-2ubuntu1.1");
    LESS("6.8.0-40.40", "6.8.0-41.41");
    LESS("1.2.3-1", "1.2.3-10");

    /* Scan.
     *  a: same version offered                -> fine
     *  b: newer version in the archive        -> upgradable
     *  c: not offered at all                  -> obsolete
     *  d: only config files left              -> ignored
     *  linux-image-6.8.0-40-generic: gone     -> ignored (kept as fallback)
     *  e: newer only in backports (NotAutomatic, priority 100 < 500) -> fine
     *  f: newer only as a 10 % phased update  -> fine
     *  g: on hold, same version offered       -> fine
     *  h: installed 1:0.5 is newer than any offered (2.0) -> obsolete
     *  firefox: 159 from packages.mozilla.org; archive has 1:1snap1
     *  thunderbird: 137, only offered as archive 1:1snap1 */
    gaudit_deb_counts counts = { 99, 99 };

    /* Without preferences, the snap transitional packages (epoch 1) look
     * like upgrades for firefox and thunderbird. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 3);
    CHECK(counts.obsolete == 2);

    /* With a common pinning setup (mozilla at 1000, Ubuntu's firefox and thunderbird at -1):
     * nothing to upgrade there, and thunderbird is left without a source,
     * exactly as apt reports it. The .bak file is ignored, as apt does. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", DATA "/no-such-preferences",
                          DATA "/preferences.d", &counts) == GAUDIT_BACKEND_OK);
    CHECK(counts.upgradable == 1);
    CHECK(counts.obsolete == 3);

    /* The obsolete callback reports exactly the counted packages. */
    unsigned reported = 0;
    CHECK(gaudit_deb_scan_ex(DATA "/status", DATA "/lists", NULL, DATA "/preferences.d",
                             &counts, count_reported, &reported) == GAUDIT_BACKEND_OK);
    CHECK(reported == 3);

    /* Pinning we cannot follow: no guess. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-regex.d", &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, DATA "/preferences-label.d", &counts)
          == GAUDIT_BACKEND_ERROR);

    /* Partly compressed indexes would give wrong counts: cannot tell. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-mixed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Only compressed indexes, or no lists at all: cannot tell. */
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists-compressed", NULL, NULL, &counts)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/no-such-dir", NULL, NULL, &counts)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Unreadable status file and bad arguments. */
    CHECK(gaudit_deb_scan(DATA "/no-such-status", DATA "/lists", NULL, NULL, &counts)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(NULL, DATA "/lists", NULL, NULL, &counts) == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_deb_scan(DATA "/status", DATA "/lists", NULL, NULL, NULL) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
