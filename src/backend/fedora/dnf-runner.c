/* SPDX-License-Identifier: GPL-3.0-only */
#include "dnf-runner.h"

#include "collector.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_COUNT  10000000LL

int gaudit_dnf_parse(const char *text, gaudit_dnf_state *out)
{
    if (out == NULL)
        return -1;
    long long installed, upgradable, extras, above;
    const gaudit_sexpr_field fields[] = {
        { .key = "installed",  .value = &installed,  .max = MAX_COUNT },
        { .key = "upgradable", .value = &upgradable, .max = MAX_COUNT },
        { .key = "extras",     .value = &extras,     .max = MAX_COUNT },
        { .key = "above",      .value = &above,      .max = MAX_COUNT },
    };
    if (gaudit_sexpr_parse(text, "dnf", fields, sizeof fields / sizeof fields[0]) != 0
        || upgradable > installed || extras + above > installed)
        return -1;
    out->installed = (unsigned)installed;
    out->upgradable = (unsigned)upgradable;
    out->extras = (unsigned)extras;
    out->above = (unsigned)above;
    return 0;
}

#define MAX_LIST_OUTPUT (512 * 1024)

gaudit_backend_status gaudit_dnf_run_list(const char *dnf_bin, const char *probe_path,
                                          int timeout_ms, gaudit_sourceless_fn fn, void *ctx)
{
    if (dnf_bin == NULL || probe_path == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(dnf_bin, X_OK) != 0)
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

gaudit_backend_status gaudit_dnf_run_probe(const char *dnf_bin, const char *probe_path,
                                           int timeout_ms, gaudit_dnf_state *out)
{
    if (dnf_bin == NULL || probe_path == NULL || out == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(dnf_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;

    char buf[MAX_OUTPUT];
    gaudit_backend_status status = gaudit_collector_run(probe_path, timeout_ms, buf, sizeof buf);
    if (status != GAUDIT_BACKEND_OK)
        return status;
    return gaudit_dnf_parse(buf, out) == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
