/* SPDX-License-Identifier: GPL-3.0-only */
/* The helper's lease: 2 minutes after the last run, never beyond 30
 * minutes after the password, on a clock given by the test. */
#include "lease.h"

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

#define MIN (60LL * 1000)

int main(void)
{
    gaudit_lease l;
    long long wait = -1;
    gaudit_lease_begin(&l, 1000);

    /* Fresh: live, waiting at most the idle time. */
    CHECK(gaudit_lease_check(&l, 1000, &wait) == GAUDIT_LEASE_LIVE && wait == 2 * MIN);
    CHECK(gaudit_lease_check(&l, 1000 + 2 * MIN - 1, NULL) == GAUDIT_LEASE_LIVE);
    CHECK(gaudit_lease_check(&l, 1000 + 2 * MIN, NULL) == GAUDIT_LEASE_IDLE);

    /* Each run within the idle time renews it, again and again ... */
    long long t = 1000;
    for (int i = 0; i < 15; i++) {
        t += 2 * MIN - 1000;
        CHECK(gaudit_lease_check(&l, t, NULL) == GAUDIT_LEASE_LIVE);
        gaudit_lease_renew(&l, t);
    }
    /* ... but never past the cap: now 15 s before it, the idle time
     * would reach past 30 min, so the wait is cut at the cap. */
    CHECK(gaudit_lease_check(&l, t, &wait) == GAUDIT_LEASE_LIVE);
    CHECK(t + wait == 1000 + 30 * MIN);
    gaudit_lease_renew(&l, 1000 + 30 * MIN - 1);
    CHECK(gaudit_lease_check(&l, 1000 + 30 * MIN, NULL) == GAUDIT_LEASE_CAP);
    CHECK(gaudit_lease_check(&l, 1000 + 31 * MIN, NULL) == GAUDIT_LEASE_CAP);

    /* A clock that goes backwards never lengthens the lease. */
    gaudit_lease_begin(&l, 10 * MIN);
    CHECK(gaudit_lease_check(&l, 9 * MIN, NULL) != GAUDIT_LEASE_LIVE);
    gaudit_lease_renew(&l, 5 * MIN);  /* earlier than the last: ignored */
    CHECK(l.last_ms == 10 * MIN);

    CHECK(gaudit_lease_now() > 0);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
