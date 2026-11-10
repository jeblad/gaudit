/* SPDX-License-Identifier: GPL-3.0-only */
/* os-release parsing, the display name, and the backend a distribution
 * leads us to expect (expectation only; detection chooses the backend). */
#include "os-release.h"

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

#define DATA GAUDIT_TEST_DATA_DIR "/os-release"

static const char *describe(const char *file, const gaudit_pkg_backend **backend)
{
    static char buf[256];
    gaudit_os_release os;
    int ok = gaudit_os_release_read(file, &os) == 0;
    *backend = gaudit_pkg_backend_expected_for(ok ? &os : NULL);
    gaudit_os_release_describe(ok ? &os : NULL, buf, sizeof buf);
    return buf;
}

int main(void)
{
    const gaudit_pkg_backend *b;

    CHECK(strcmp(describe(DATA "/ubuntu", &b), "Ubuntu 26.10 Stonking Stoat") == 0);
    CHECK(b == gaudit_pkg_backend_debian());

    CHECK(strcmp(describe(DATA "/mint", &b), "Linux Mint 23") == 0);  /* ID_LIKE ubuntu */
    CHECK(b == gaudit_pkg_backend_debian());

    CHECK(strcmp(describe(DATA "/fedora", &b), "Fedora Linux 44 Workstation Edition") == 0);
    CHECK(b == gaudit_pkg_backend_fedora());

    /* RHEL family lists fedora in ID_LIKE but has no dnf5: no expectation. */
    CHECK(strcmp(describe(DATA "/rocky", &b), "Rocky Linux 10.1") == 0);
    CHECK(b == NULL);

    CHECK(strcmp(describe(DATA "/arch", &b), "Arch Linux") == 0);  /* no VERSION_ID */
    CHECK(b == gaudit_pkg_backend_arch());

    CHECK(strcmp(describe(DATA "/manjaro", &b), "Manjaro Linux") == 0);  /* ID_LIKE arch */
    CHECK(b == gaudit_pkg_backend_arch());

    CHECK(strcmp(describe(DATA "/tumbleweed", &b), "openSUSE Tumbleweed 20261101") == 0);
    CHECK(b == NULL);

    /* Whole words only: "debianish"/"notdebian" are not Debian. Escapes. */
    CHECK(strcmp(describe(DATA "/tricky", &b), "Quote \"test\" \\ and $x") == 0);
    CHECK(b == NULL);

    /* Control characters are dropped. */
    CHECK(strcmp(describe(DATA "/control", &b), "BadName 1") == 0);

    /* Unknown: empty or missing file. */
    CHECK(strcmp(describe(DATA "/empty", &b), "") == 0);
    CHECK(b == NULL);
    CHECK(strcmp(describe(DATA "/no-such-file", &b), "") == 0);
    CHECK(b == NULL);

    /* Short names. */
    gaudit_os_release u;
    char name[64];
    CHECK(gaudit_os_release_read(DATA "/ubuntu", &u) == 0);
    gaudit_os_release_name(&u, name, sizeof name);
    CHECK(strcmp(name, "Ubuntu") == 0);
    gaudit_os_release_name(NULL, name, sizeof name);
    CHECK(strcmp(name, "") == 0);

    /* Not a regular file. */
    gaudit_os_release os;
    CHECK(gaudit_os_release_read(DATA, &os) != 0);

    /* The generic backend has no package checks, but does know Flatpak. */
    const gaudit_pkg_backend *g = gaudit_pkg_backend_generic();
    CHECK(g->package_state == NULL && g->automatic_updates == NULL && g->last_index_update == NULL);
    CHECK(g->flatpak_state != NULL && g->capability != NULL && g->capability("ufw") != NULL);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
