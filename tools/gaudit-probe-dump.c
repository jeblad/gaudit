/* SPDX-License-Identifier: GPL-3.0-only */
/* Developer tool (dev builds only): runs the Home status probes against this
 * machine and lists the packages counted as having no source, so the
 * results can be compared with apt. Read-only; needs no privileges. */
#include "gaudit/probe.h"

#include "dpkg.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *const verdict_names[] = { "ok", "unknown", "warning", "critical" };

static void print_obsolete(const char *name, const char *arch, const char *version,
                           gaudit_deb_group group, const char *offered, void *ctx)
{
    static const char *const groups[] = { "above-source", "leftover", "other-source" };
    (void)ctx;
    if (offered != NULL)
        printf("  %-12s %s:%s %s  (offered: %s)\n", groups[group], name, arch, version, offered);
    else
        printf("  %-12s %s:%s %s\n", groups[group], name, arch, version);
}

int main(void)
{
    char host[256], name[256], full[256];
    gaudit_system_describe(host, sizeof host, name, sizeof name, full, sizeof full);
    printf("System:  %s (%s) [%s]\nBackend: %s\n", host[0] ? host : "?", name[0] ? name : "unknown",
           full, gaudit_pkg_backend_default()->name);

    gaudit_probe_result r[GAUDIT_PROBE_COUNT];
    const gaudit_pkg_backend *expected = gaudit_pkg_backend_expected();
    printf("Expected backend: %s\n", expected ? expected->name : "(none)");
    gaudit_probe_collect_ex(gaudit_pkg_backend_default(), expected, (int64_t)time(NULL), r);

    printf("Probes:\n");
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++)
        printf("  %-26s %-8s count=%u/%u/%u age=%.1fd%s%s\n", r[k].id, verdict_names[r[k].verdict],
               r[k].count, r[k].extra_count, r[k].info_count, (double)r[k].age_seconds / 86400.0,
               r[k].applicable ? "" : " not-applicable", r[k].unsupported ? " unsupported" : "");

    unsigned present = gaudit_package_systems_present_here();
    printf("Package systems present:");
    for (int s = 0; s < GAUDIT_PKGSYS_COUNT; s++)
        if (present & (1u << s))
            printf(" [%s]", gaudit_package_system_label((gaudit_package_system)s));
    printf("\n");

    if (strcmp(gaudit_pkg_backend_default()->name, "debian") != 0)
        return 0;  /* the package list below is dpkg-specific */

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
