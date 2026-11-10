/* SPDX-License-Identifier: GPL-3.0-only */
/* Detecting package systems by their databases, on fixture trees in
 * tests/data/pkgsys/<case>/ used as the filesystem root. */
#include "gaudit/backend.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

#define BIT(s) (1u << (s))
#define ROOT(c) GAUDIT_TEST_DATA_DIR "/pkgsys/" c

int main(void)
{
    CHECK(gaudit_package_systems_present(ROOT("debian")) == BIT(GAUDIT_PKGSYS_DPKG));

    /* Ubuntu with rpm next to it, and Nix. */
    CHECK(gaudit_package_systems_present(ROOT("mixed"))
          == (BIT(GAUDIT_PKGSYS_DPKG) | BIT(GAUDIT_PKGSYS_RPM) | BIT(GAUDIT_PKGSYS_NIX)));

    /* rpm database in its newer place. */
    CHECK(gaudit_package_systems_present(ROOT("fedora-new")) == BIT(GAUDIT_PKGSYS_RPM));

    /* Slackware, old and new location of the package list. */
    CHECK(gaudit_package_systems_present(ROOT("slackware-old")) == BIT(GAUDIT_PKGSYS_PKGTOOLS));
    CHECK(gaudit_package_systems_present(ROOT("slackware-new")) == BIT(GAUDIT_PKGSYS_PKGTOOLS));

    /* pacman: package directories count, the version file alone does not. */
    CHECK(gaudit_package_systems_present(ROOT("arch")) == BIT(GAUDIT_PKGSYS_PACMAN));
    CHECK(gaudit_package_systems_present(ROOT("arch-empty")) == 0);

    /* An empty database file is no sign of installed packages. */
    CHECK(gaudit_package_systems_present(ROOT("empty-rpm")) == 0);

    CHECK(gaudit_package_systems_present(ROOT("void")) == BIT(GAUDIT_PKGSYS_XBPS));
    CHECK(gaudit_package_systems_present(ROOT("none")) == 0);
    CHECK(gaudit_package_systems_present(ROOT("no-such-root")) == 0);

    /* Labels. */
    CHECK(strcmp(gaudit_package_system_label(GAUDIT_PKGSYS_RPM), "rpm") == 0);
    CHECK(strcmp(gaudit_package_system_label(GAUDIT_PKGSYS_COUNT), "?") == 0);
    for (int s = 0; s < GAUDIT_PKGSYS_COUNT; s++)
        CHECK(gaudit_package_system_label((gaudit_package_system)s) != NULL
              && strcmp(gaudit_package_system_label((gaudit_package_system)s), "?") != 0);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
