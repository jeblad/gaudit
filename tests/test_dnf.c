/* SPDX-License-Identifier: GPL-3.0-only */
/* The dnf collector protocol: parser and runner with fake collectors in
 * tests/data/dnf/. The real collector is exercised by tools/distro-test.sh. */
#include "dnf-runner.h"

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

#define DATA GAUDIT_TEST_DATA_DIR "/dnf"
#define PRESENT "/bin/sh"  /* stands in for /usr/bin/dnf5 */

typedef struct {
    unsigned n;
    unsigned groups[GAUDIT_SOURCELESS_GROUPS];
    char first_offered[96];
} list_seen;

static void on_package(const char *name, const char *arch, const char *version,
                       gaudit_sourceless_group group, const char *offered, void *ctx)
{
    (void)name; (void)arch; (void)version;
    list_seen *s = ctx;
    if (s->n++ == 0 && offered != NULL)
        snprintf(s->first_offered, sizeof s->first_offered, "%s", offered);
    s->groups[group]++;
}

int main(void)
{
    gaudit_dnf_state st;

    CHECK(gaudit_dnf_parse("(dnf (installed 10) (upgradable 2) (extras 1) (above 3))", &st) == 0);
    CHECK(st.installed == 10 && st.upgradable == 2 && st.extras == 1 && st.above == 3);
    CHECK(gaudit_dnf_parse("(dnf (installed 10) (upgradable 2) (extras 1))", &st) != 0);
    CHECK(gaudit_dnf_parse("(dnf (installed 1) (upgradable 0) (extras 1) (above 1))", &st) != 0);
    CHECK(gaudit_dnf_parse("(apt (installed 1) (upgradable 0) (extras 0) (above 0))", &st) != 0);

    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/ok.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.installed == 1800 && st.upgradable == 12 && st.extras == 3 && st.above == 1);
    CHECK(gaudit_dnf_run_probe("/nonexistent/dnf5", DATA "/ok.sh", 2000, &st)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/no-such-collector", 2000, &st)
          == GAUDIT_BACKEND_NOT_IMPLEMENTED);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/missing-library.sh", 2000, &st)
          == GAUDIT_BACKEND_MISSING_DEPENDENCY);
    CHECK(gaudit_dnf_run_probe(PRESENT, DATA "/inconsistent.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);

    /* The list: every line strictly, groups kept, the count must match. */
    list_seen seen = { 0 };
    CHECK(gaudit_dnf_run_list(PRESENT, DATA "/ok.sh", 2000, on_package, &seen) == GAUDIT_BACKEND_OK);
    CHECK(seen.n == 4 && seen.groups[0] == 1 && seen.groups[1] == 1 && seen.groups[2] == 2);
    CHECK(strcmp(seen.first_offered, "1.0.8-18.fc45") == 0);
    CHECK(gaudit_dnf_run_list(PRESENT, DATA "/inconsistent.sh", 2000, on_package, &seen)
          == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_dnf_run_list("/nonexistent/dnf5", DATA "/ok.sh", 2000, on_package, &seen)
          == GAUDIT_BACKEND_UNAVAILABLE);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
