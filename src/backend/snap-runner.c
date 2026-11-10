/* SPDX-License-Identifier: GPL-3.0-only */
#include "snap-runner.h"

#include "collector.h"

#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_COUNT  1000000LL
#define MAX_EPOCH  32503680000LL  /* year 3000 */

int gaudit_snap_parse(const char *text, gaudit_snap_state *out)
{
    if (out == NULL)
        return -1;
    long long running, snaps, devmode, classic, held, last_refresh, refresh_hold;
    const gaudit_sexpr_field fields[] = {
        { .key = "running",      .value = &running,      .max = 1 },
        { .key = "snaps",        .value = &snaps,        .max = MAX_COUNT },
        { .key = "devmode",      .value = &devmode,      .max = MAX_COUNT },
        { .key = "classic",      .value = &classic,      .max = MAX_COUNT },
        { .key = "held",         .value = &held,         .max = MAX_COUNT },
        { .key = "last-refresh", .value = &last_refresh, .max = MAX_EPOCH },
        { .key = "refresh-hold", .value = &refresh_hold, .max = MAX_EPOCH },
    };
    if (gaudit_sexpr_parse(text, "snap", fields, sizeof fields / sizeof fields[0]) != 0
        || devmode + classic > snaps || held > snaps)
        return -1;
    out->running = (int)running;
    out->snaps = (unsigned)snaps;
    out->devmode = (unsigned)devmode;
    out->classic = (unsigned)classic;
    out->held = (unsigned)held;
    out->last_refresh = last_refresh;
    out->refresh_hold = refresh_hold;
    return 0;
}

gaudit_backend_status gaudit_snap_run_probe(const char *snap_bin, const char *probe_path,
                                            int timeout_ms, gaudit_snap_state *out)
{
    if (snap_bin == NULL || probe_path == NULL || out == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(snap_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;

    char buf[MAX_OUTPUT];
    gaudit_backend_status status = gaudit_collector_run(probe_path, timeout_ms, buf, sizeof buf);
    if (status != GAUDIT_BACKEND_OK)
        return status;
    return gaudit_snap_parse(buf, out) == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
