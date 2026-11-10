/* SPDX-License-Identifier: GPL-3.0-only */
/* Exercises the model's C API from C, i.e. across the C/C++ boundary. */
#include "gaudit/model.h"

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

int main(void)
{
    gaudit_model *m = NULL;

    CHECK(gaudit_model_new(NULL) == GAUDIT_ERR_INVALID);
    CHECK(gaudit_model_new(&m) == GAUDIT_OK);
    if (m == NULL)
        return 1;

    /* Empty model: nothing known. */
    CHECK(gaudit_model_count(m) == 0);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_UNKNOWN);

    /* Worst verdict wins, regardless of order. */
    CHECK(gaudit_model_add_finding(m, "firewall.active", GAUDIT_VERDICT_OK) == GAUDIT_OK);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_OK);
    CHECK(gaudit_model_add_finding(m, "av.scheduled", GAUDIT_VERDICT_WARNING) == GAUDIT_OK);
    CHECK(gaudit_model_add_finding(m, "updates.recent", GAUDIT_VERDICT_OK) == GAUDIT_OK);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_WARNING);
    CHECK(gaudit_model_count(m) == 3);

    /* Run again: the new result replaces the old, in both directions. */
    CHECK(gaudit_model_add_finding(m, "av.scheduled", GAUDIT_VERDICT_OK) == GAUDIT_OK);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_OK);
    CHECK(gaudit_model_add_finding(m, "firewall.active", GAUDIT_VERDICT_CRITICAL) == GAUDIT_OK);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_CRITICAL);
    CHECK(gaudit_model_add_finding(m, "firewall.active", GAUDIT_VERDICT_OK) == GAUDIT_OK);
    CHECK(gaudit_model_count(m) == 3);

    /* The summary: one unknown makes it unknown, even next to a warning. */
    CHECK(gaudit_model_summary(m) == GAUDIT_VERDICT_OK);
    CHECK(gaudit_model_add_finding(m, "av.scheduled", GAUDIT_VERDICT_WARNING) == GAUDIT_OK);
    CHECK(gaudit_model_summary(m) == GAUDIT_VERDICT_WARNING);
    CHECK(gaudit_model_add_finding(m, "updates.recent", GAUDIT_VERDICT_UNKNOWN) == GAUDIT_OK);
    CHECK(gaudit_model_worst(m) == GAUDIT_VERDICT_WARNING);
    CHECK(gaudit_model_summary(m) == GAUDIT_VERDICT_UNKNOWN);
    CHECK(gaudit_model_add_finding(m, "updates.recent", GAUDIT_VERDICT_OK) == GAUDIT_OK);
    CHECK(gaudit_model_add_finding(m, "av.scheduled", GAUDIT_VERDICT_OK) == GAUDIT_OK);

    /* Invalid input is rejected and leaves the model unchanged. */
    CHECK(gaudit_model_add_finding(m, NULL, GAUDIT_VERDICT_OK) == GAUDIT_ERR_INVALID);
    CHECK(gaudit_model_add_finding(m, "", GAUDIT_VERDICT_OK) == GAUDIT_ERR_INVALID);
    CHECK(gaudit_model_add_finding(m, "x", (gaudit_verdict)42) == GAUDIT_ERR_INVALID);
    CHECK(gaudit_model_add_finding(NULL, "x", GAUDIT_VERDICT_OK) == GAUDIT_ERR_INVALID);
    CHECK(gaudit_model_count(m) == 3);

    /* NULL-tolerant accessors. */
    CHECK(gaudit_model_count(NULL) == 0);
    CHECK(gaudit_model_worst(NULL) == GAUDIT_VERDICT_UNKNOWN);
    CHECK(gaudit_model_summary(NULL) == GAUDIT_VERDICT_UNKNOWN);
    gaudit_model_free(NULL);

    gaudit_model_free(m);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
