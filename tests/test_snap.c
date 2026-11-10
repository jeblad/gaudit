/* SPDX-License-Identifier: GPL-3.0-only */
/* The Snap collector protocol (parser and runner with fake collectors in
 * tests/data/snap/), and the shared S-expression parser. */
#include "collector.h"
#include "snap-runner.h"

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

#define DATA GAUDIT_TEST_DATA_DIR "/snap"
#define PRESENT "/bin/sh"  /* stands in for /usr/bin/snap */

#define FULL(extra) "(snap (running 1) (snaps 5) (devmode 1) (classic 1) (held 0)" \
                    " (last-refresh 1794268080) (refresh-hold 0)" extra ")"

int main(void)
{
    gaudit_snap_state st;

    /* Parser: accepted. */
    CHECK(gaudit_snap_parse(FULL(""), &st) == 0);
    CHECK(st.running == 1 && st.snaps == 5 && st.devmode == 1 && st.classic == 1);
    CHECK(st.held == 0 && st.last_refresh == 1794268080LL && st.refresh_hold == 0);

    /* Parser: rejected. */
    CHECK(gaudit_snap_parse(FULL(" (extra 1)"), &st) != 0);
    CHECK(gaudit_snap_parse("(snap (running 1))", &st) != 0);
    CHECK(gaudit_snap_parse("(snap (running 2) (snaps 0) (devmode 0) (classic 0) (held 0)"
                            " (last-refresh 0) (refresh-hold 0))", &st) != 0);   /* running is 0/1 */
    CHECK(gaudit_snap_parse("(snap (running 1) (snaps 1) (devmode 1) (classic 1) (held 0)"
                            " (last-refresh 0) (refresh-hold 0))", &st) != 0);   /* more than snaps */
    CHECK(gaudit_snap_parse("(snap (running 1) (snaps 1) (devmode 0) (classic 0) (held 0)"
                            " (last-refresh 99999999999999) (refresh-hold 0))", &st) != 0);
    CHECK(gaudit_snap_parse("(flatpak (apps 1))", &st) != 0);

    /* Shared parser: a key that is a prefix of the head, and unknown heads. */
    long long v = 0;
    const gaudit_sexpr_field one[] = { { .key = "n", .value = &v, .max = 10 } };
    CHECK(gaudit_sexpr_parse("(x (n 10))", "x", one, 1) == 0 && v == 10);
    CHECK(gaudit_sexpr_parse("(x (n 11))", "x", one, 1) != 0);   /* above max */
    CHECK(gaudit_sexpr_parse("(xy (n 1))", "x", one, 1) != 0);
    CHECK(gaudit_sexpr_parse("(x (n 1)", "x", one, 1) != 0);

    /* Runner. */
    CHECK(gaudit_snap_run_probe(PRESENT, DATA "/ok.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.snaps == 31 && st.devmode == 1 && st.classic == 2 && st.held == 3);
    CHECK(gaudit_snap_run_probe(PRESENT, DATA "/not-running.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.running == 0);
    CHECK(gaudit_snap_run_probe("/nonexistent/snap", DATA "/ok.sh", 2000, &st)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_snap_run_probe(PRESENT, DATA "/no-such-collector", 2000, &st)
          == GAUDIT_BACKEND_NOT_IMPLEMENTED);
    CHECK(gaudit_snap_run_probe(PRESENT, DATA "/missing-library.sh", 2000, &st)
          == GAUDIT_BACKEND_MISSING_DEPENDENCY);
    CHECK(gaudit_snap_run_probe(PRESENT, DATA "/partial.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
