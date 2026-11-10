/* SPDX-License-Identifier: GPL-3.0-only */
/* How long the helper keeps its elevated rights in a session. Enforced by
 * the helper itself (root); nothing on the user's side can stretch it.
 *
 * Idle: the rights end GAUDIT_LEASE_IDLE_MS after the last run finished;
 * each new run within that time renews it. Cap: never beyond
 * GAUDIT_LEASE_CAP_MS after the password was given; a run under way when
 * the cap is reached may finish, then the rights end. Times are
 * CLOCK_BOOTTIME milliseconds, so time asleep counts too. */
#pragma once

#define GAUDIT_LEASE_IDLE_MS (2LL * 60 * 1000)
#define GAUDIT_LEASE_CAP_MS  (30LL * 60 * 1000)

typedef enum {
    GAUDIT_LEASE_LIVE = 0,
    GAUDIT_LEASE_IDLE,   /* no run within the idle time */
    GAUDIT_LEASE_CAP,    /* the cap is reached */
} gaudit_lease_state;

typedef struct {
    long long started_ms;  /* when the password was given */
    long long last_ms;     /* when the last run finished (or started_ms) */
} gaudit_lease;

void gaudit_lease_begin(gaudit_lease *l, long long now_ms);

/* A run has finished at now_ms: the idle time starts again. */
void gaudit_lease_renew(gaudit_lease *l, long long now_ms);

/* Whether a new run may start at now_ms; if so, *wait_ms (may be NULL) is
 * how long to wait for one at most. */
gaudit_lease_state gaudit_lease_check(const gaudit_lease *l, long long now_ms, long long *wait_ms);

/* CLOCK_BOOTTIME in milliseconds. */
long long gaudit_lease_now(void);
