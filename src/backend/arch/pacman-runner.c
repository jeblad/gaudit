/* SPDX-License-Identifier: GPL-3.0-only */
#include "pacman-runner.h"

#include "collector.h"

#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_COUNT  10000000LL

int gaudit_pacman_parse(const char *text, gaudit_pacman_state *out)
{
    if (out == NULL)
        return -1;
    long long installed, upgradable, foreign;
    const gaudit_sexpr_field fields[] = {
        { .key = "installed",  .value = &installed,  .max = MAX_COUNT },
        { .key = "upgradable", .value = &upgradable, .max = MAX_COUNT },
        { .key = "foreign",    .value = &foreign,    .max = MAX_COUNT },
    };
    if (gaudit_sexpr_parse(text, "pacman", fields, sizeof fields / sizeof fields[0]) != 0
        || upgradable + foreign > installed)
        return -1;
    out->installed = (unsigned)installed;
    out->upgradable = (unsigned)upgradable;
    out->foreign = (unsigned)foreign;
    return 0;
}

gaudit_backend_status gaudit_pacman_run_probe(const char *pacman_bin, const char *probe_path,
                                              int timeout_ms, gaudit_pacman_state *out)
{
    if (pacman_bin == NULL || probe_path == NULL || out == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(pacman_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;

    char buf[MAX_OUTPUT];
    gaudit_backend_status status = gaudit_collector_run(probe_path, timeout_ms, buf, sizeof buf);
    if (status != GAUDIT_BACKEND_OK)
        return status;
    return gaudit_pacman_parse(buf, out) == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
