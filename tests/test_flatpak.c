/* SPDX-License-Identifier: GPL-3.0-only */
/* The Flatpak collector protocol: the strict parser, and running a collector
 * as a separate process (fake collectors in tests/data/flatpak/). */
#include "flatpak-runner.h"

#include <stdio.h>
#include <stdlib.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define DATA GAUDIT_TEST_DATA_DIR "/flatpak"
#define PRESENT "/bin/sh"  /* stands in for /usr/bin/flatpak */

static gaudit_backend_status run(const char *script, int timeout_ms, gaudit_flatpak_state *st)
{
    return gaudit_flatpak_run_probe(PRESENT, script, timeout_ms, st);
}

int main(void)
{
    gaudit_flatpak_state st;

    /* Parser: accepted. */
    CHECK(gaudit_flatpak_parse("(flatpak (apps 12) (eol-apps 3) (eol-unused 4) (eol-pinned 1))\n", &st) == 0);
    CHECK(st.apps == 12 && st.eol_apps == 3 && st.eol_unused == 4 && st.eol_pinned == 1);
    CHECK(gaudit_flatpak_parse("  (flatpak\n  (eol-unused 0)\n  (apps 0)\n  (eol-pinned 0) (eol-apps 0))  ", &st) == 0);

    /* Parser: rejected. */
    CHECK(gaudit_flatpak_parse("", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpakx (apps 1) (eol-apps 0) (eol-unused 0) (eol-pinned 0))", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 0))", &st) != 0);              /* keys missing */
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 0) (eol-unused 0))", &st) != 0); /* eol-pinned missing */
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (apps 1) (eol-apps 0) (eol-unused 0) (eol-pinned 0))", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 0) (eol-unused 0) (eol-pinned 0) (extra 1))", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps -1) (eol-apps 0) (eol-unused 0) (eol-pinned 0))", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps 99999999999) (eol-apps 0) (eol-unused 0) (eol-pinned 0))", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 2) (eol-unused 0) (eol-pinned 0))", &st) != 0); /* more eol than apps */
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 0) (eol-unused 0) (eol-pinned 0)) junk", &st) != 0);
    CHECK(gaudit_flatpak_parse("(flatpak (apps 1) (eol-apps 0) (eol-unused 0) (eol-pinned 0)", &st) != 0);  /* unclosed */
    CHECK(gaudit_flatpak_parse(NULL, &st) != 0);

    /* Runner: normal answer. */
    CHECK(run(DATA "/ok.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.apps == 12 && st.eol_apps == 3 && st.eol_unused == 4 && st.eol_pinned == 1);

    /* Runner: Flatpak not in use, collector not built, library missing. */
    CHECK(gaudit_flatpak_run_probe("/nonexistent/flatpak", DATA "/ok.sh", 2000, &st)
          == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(run(DATA "/no-such-collector", 2000, &st) == GAUDIT_BACKEND_NOT_IMPLEMENTED);
    CHECK(run(DATA "/missing-library.sh", 2000, &st) == GAUDIT_BACKEND_MISSING_DEPENDENCY);

    /* Runner: failures, bad output, too much output, timeouts. */
    CHECK(run(DATA "/fails.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);
    CHECK(run(DATA "/garbage.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);
    CHECK(run(DATA "/floods.sh", 2000, &st) == GAUDIT_BACKEND_ERROR);
    CHECK(run(DATA "/hangs.sh", 300, &st) == GAUDIT_BACKEND_ERROR);
    CHECK(run(DATA "/lingers.sh", 300, &st) == GAUDIT_BACKEND_ERROR);  /* answers, then never exits */

    /* Runner: the caller's environment does not leak, HOME is set. */
    setenv("GAUDIT_TEST_LEAK", "1", 1);
    CHECK(run(DATA "/environment.sh", 2000, &st) == GAUDIT_BACKEND_OK);
    CHECK(st.apps == 1);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
