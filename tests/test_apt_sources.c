/* SPDX-License-Identifier: GPL-3.0-only */
/* Where security updates come from, on list directories in
 * tests/data/apt-sources/<case>/ (empty files; only the names matter). */
#include "apt-sources.h"

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

#define DATA GAUDIT_TEST_DATA_DIR "/apt-sources"

int main(void)
{
    unsigned official, mirror;
    char host[64];

    /* A country mirror for the archive, security straight from Ubuntu. */
    CHECK(gaudit_apt_security_sources(DATA "/official", &official, &mirror, host, sizeof host)
          == GAUDIT_BACKEND_OK);
    CHECK(official == 1 && mirror == 0 && host[0] == '\0');

    /* Security from the country mirror too: the setup that lagged behind. */
    CHECK(gaudit_apt_security_sources(DATA "/mirror", &official, &mirror, host, sizeof host)
          == GAUDIT_BACKEND_OK);
    CHECK(official == 0 && mirror == 1 && strcmp(host, "no.archive.ubuntu.com") == 0);

    /* Debian's security archive on deb.debian.org. */
    CHECK(gaudit_apt_security_sources(DATA "/debian", &official, &mirror, host, sizeof host)
          == GAUDIT_BACKEND_OK);
    CHECK(official == 1 && mirror == 0);

    /* No security suite at all (Debian unstable). */
    CHECK(gaudit_apt_security_sources(DATA "/none", &official, &mirror, host, sizeof host)
          == GAUDIT_BACKEND_OK);
    CHECK(official == 0 && mirror == 0);

    CHECK(gaudit_apt_security_sources(DATA "/no-such-dir", &official, &mirror, host, sizeof host)
          == GAUDIT_BACKEND_UNAVAILABLE);

    /* Exact host names only: a look-alike is not official. */
    CHECK(gaudit_apt_official_security_host("security.ubuntu.com"));
    CHECK(!gaudit_apt_official_security_host("security.ubuntu.com.example.net"));
    CHECK(!gaudit_apt_official_security_host("no.archive.ubuntu.com"));

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
