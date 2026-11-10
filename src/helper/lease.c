/* SPDX-License-Identifier: GPL-3.0-only */
#include "lease.h"

#include <time.h>

void gaudit_lease_begin(gaudit_lease *l, long long now_ms)
{
    l->started_ms = now_ms;
    l->last_ms = now_ms;
}

void gaudit_lease_renew(gaudit_lease *l, long long now_ms)
{
    if (now_ms > l->last_ms)
        l->last_ms = now_ms;
}

gaudit_lease_state gaudit_lease_check(const gaudit_lease *l, long long now_ms, long long *wait_ms)
{
    long long cap_left = l->started_ms + GAUDIT_LEASE_CAP_MS - now_ms;
    long long idle_left = l->last_ms + GAUDIT_LEASE_IDLE_MS - now_ms;
    /* A clock that went backwards counts as expired: never longer. */
    if (cap_left <= 0 || now_ms < l->started_ms)
        return GAUDIT_LEASE_CAP;
    if (idle_left <= 0 || now_ms < l->last_ms)
        return GAUDIT_LEASE_IDLE;
    if (wait_ms != NULL)
        *wait_ms = cap_left < idle_left ? cap_left : idle_left;
    return GAUDIT_LEASE_LIVE;
}

long long gaudit_lease_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
        return -1;
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
