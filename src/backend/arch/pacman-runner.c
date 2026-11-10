/* SPDX-License-Identifier: GPL-3.0-only */
#include "pacman-runner.h"

#include "collector.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_COUNT  10000000LL

int gaudit_pacman_parse(const char *text, gaudit_pacman_state *out)
{
    if (out == NULL)
        return -1;
    long long installed, upgradable, foreign, above;
    const gaudit_sexpr_field fields[] = {
        { .key = "installed",  .value = &installed,  .max = MAX_COUNT },
        { .key = "upgradable", .value = &upgradable, .max = MAX_COUNT },
        { .key = "foreign",    .value = &foreign,    .max = MAX_COUNT },
        { .key = "above",      .value = &above,      .max = MAX_COUNT },
    };
    if (gaudit_sexpr_parse(text, "pacman", fields, sizeof fields / sizeof fields[0]) != 0
        || upgradable + foreign + above > installed)
        return -1;
    out->installed = (unsigned)installed;
    out->upgradable = (unsigned)upgradable;
    out->foreign = (unsigned)foreign;
    out->above = (unsigned)above;
    return 0;
}

#define MAX_LIST_OUTPUT (512 * 1024)

gaudit_backend_status gaudit_pacman_run_list(const char *pacman_bin, const char *probe_path,
                                             int timeout_ms, gaudit_sourceless_fn fn, void *ctx)
{
    if (pacman_bin == NULL || probe_path == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(pacman_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;
    char *buf = malloc(MAX_LIST_OUTPUT);
    if (buf == NULL)
        return GAUDIT_BACKEND_ERROR;
    gaudit_backend_status status =
        gaudit_collector_run_arg(probe_path, "list", timeout_ms, buf, MAX_LIST_OUTPUT);
    if (status == GAUDIT_BACKEND_OK)
        status = gaudit_collector_sourceless(buf, fn, ctx);
    free(buf);
    return status;
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
