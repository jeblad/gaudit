/* SPDX-License-Identifier: GPL-3.0-only */
#include "flatpak-runner.h"

#include "collector.h"

#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_COUNT  1000000LL

int gaudit_flatpak_parse(const char *text, gaudit_flatpak_state *out)
{
    if (out == NULL)
        return -1;
    long long apps, eol_apps, eol_unused, eol_pinned;
    const gaudit_sexpr_field fields[] = {
        { "apps",       &apps,       MAX_COUNT },
        { "eol-apps",   &eol_apps,   MAX_COUNT },
        { "eol-unused", &eol_unused, MAX_COUNT },
        { "eol-pinned", &eol_pinned, MAX_COUNT },
    };
    if (gaudit_sexpr_parse(text, "flatpak", fields, sizeof fields / sizeof fields[0]) != 0
        || eol_apps > apps)
        return -1;
    out->apps = (unsigned)apps;
    out->eol_apps = (unsigned)eol_apps;
    out->eol_unused = (unsigned)eol_unused;
    out->eol_pinned = (unsigned)eol_pinned;
    return 0;
}

gaudit_backend_status gaudit_flatpak_run_probe(const char *flatpak_bin, const char *probe_path,
                                               int timeout_ms, gaudit_flatpak_state *out)
{
    if (flatpak_bin == NULL || probe_path == NULL || out == NULL)
        return GAUDIT_BACKEND_ERROR;
    if (access(flatpak_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;

    char buf[MAX_OUTPUT];
    gaudit_backend_status status = gaudit_collector_run(probe_path, timeout_ms, buf, sizeof buf);
    if (status != GAUDIT_BACKEND_OK)
        return status;
    return gaudit_flatpak_parse(buf, out) == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
