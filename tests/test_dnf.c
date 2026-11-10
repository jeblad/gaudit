/* SPDX-License-Identifier: GPL-3.0-only */
/* The dnf collector protocol: parser and runner with fake collectors in
 * tests/data/dnf/. The real collector is exercised by tools/distro-test.sh. */
#include "dnf-runner.h"

#include <stdio.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define DATA GAUDIT_TEST_DATA_DIR "/dnf"
#define PRESENT "/bin/sh"  /* stands in for /usr/bin/dnf5 */

int main(void)
{
    gaudit_dnf_state st;

    CHECK(gaudit_dnf_parse("(dnf (installed 10) (upgradable 2) (extras 1))", &st) == 0);
    CHECK(st.installed == 10 && st.upgradable == 2 && st.extras == 1);
    CHECK(gaudit_dnf_parse("(dnf (installed 10) (upgradable 2))", &st) != 0);
    CHECK(gaudit_dnf_parse("(dnf (installed 1) (upgradable 0) (extras 2))", &st) != 0);  /* > installed */
    CHECK(gaudit_dnf_parse("(apt (installed 1) (upgradable 0) (extras 0))", &st) != 0);

    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/ok.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.installed == 1800 && st.upgradable == 12 && st.extras == 3);
    CHECK(gaudit_dnf_run_probe("/nonexistent/dnf5", DATA "/ok.sh", 2000, &st)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/no-such-collector", 2000, &st)
          == GAUDIT_BACKEND_NOT_IMPLEMENTED);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/missing-library.sh", 2000, &st)
          == GAUDIT_BACKEND_MISSING_DEPENDENCY);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/inconsistent.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
