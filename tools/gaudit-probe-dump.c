/* SPDX-License-Identifier: GPL-3.0-only */
/* Developer tool (dev builds only): runs the Home status probes against this
 * machine and lists the packages counted as having no source, so the
 * results can be compared with apt. Read-only; needs no privileges. */
#include "gaudit/probe.h"

#include "dpkg.h"

#include <stdio.h>
#include <time.h>

static const char *const verdict_names[] = { "ok", "unknown", "warning", "critical" };

static void print_obsolete(const char *name, const char *arch, const char *version, void *ctx)
{
    (void)ctx;
    printf("  %s:%s %s\n", name, arch, version);
}

int main(void)
{
    gaudit_probe_result r[GAUDIT_PROBE_COUNT];
    gaudit_probe_collect(gaudit_pkg_backend_default(), (int64_t)time(NULL), r);

    printf("Probes:\n");
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        printf("  %-26s %-8s count=%u age=%.1fd\n", r[k].id, verdict_names[r[k].verdict],
               r[k].count, (double)r[k].age_seconds / 86400.0);

    printf("Packages without a source:\n");
    gaudit_deb_counts counts;
    gaudit_backend_status status = gaudit_deb_scan_ex("/var/lib/dpkg/status", "/var/lib/apt/lists",
                                                      "/etc/apt/preferences", "/etc/apt/preferences.d",
                                                      &counts, print_obsolete, NULL);
    if (status != GAUDIT_BACKEND_OK) {
        printf("  scan failed (status %d)\n", (int)status);
        return 1;
    }
    printf("Total: %u without a source, %u upgradable\n", counts.obsolete, counts.upgradable);
    return 0;
}
