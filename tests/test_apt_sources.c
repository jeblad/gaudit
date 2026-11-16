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
    /* Set up, but never read: keybase; the archive and a PPA in deb822
     * are read, a disabled source and deb-src do not count, nor a file
     * apt does not read. */
    unsigned unread = 99;
    char names[128];
    CHECK(gaudit_apt_unread_sources(DATA "/unread/sources.list", DATA "/unread/sources.list.d",
                                    DATA "/unread/lists", &unread, names, sizeof names)
          == GAUDIT_BACKEND_OK);
    CHECK(unread == 1 && strcmp(names, "prerelease.keybase.io") == 0);
    /* With no lists fetched at all, every source is unread. */
    CHECK(gaudit_apt_unread_sources(DATA "/unread/sources.list", DATA "/unread/sources.list.d",
                                    DATA "/none", &unread, names, sizeof names)
          == GAUDIT_BACKEND_OK && unread == 3);
    /* A deb line that cannot be read: unknown, never a guess. */
    CHECK(gaudit_apt_unread_sources(NULL, DATA "/bad/sources.list.d", DATA "/unread/lists", &unread,
                                    names, sizeof names) == GAUDIT_BACKEND_ERROR);

    /* Switched off by the upgrade of the release: the PPA (deb822, with the
     * copy the upgrade made) and an old one-line source; not one switched
     * off by hand (no copy), one still on, or a .save file apt never reads.
     * "Enabled: yes" inside the signing key is not the source's. */
    unsigned off = 99;
    char off_names[128];
    CHECK(gaudit_apt_upgrade_disabled_sources(DATA "/upgraded/sources.list.d", &off, off_names,
                                              sizeof off_names) == GAUDIT_BACKEND_OK);
    CHECK(off == 2 && strstr(off_names, "ppa:cappelikan/ppa") != NULL
          && strstr(off_names, "legacy.example.org") != NULL);
    CHECK(gaudit_apt_upgrade_disabled_sources(DATA "/no-such", &off, off_names, sizeof off_names)
          == GAUDIT_BACKEND_OK && off == 0);

    /* distro-info: the series to its version; the pocket left off. */
    char ver[16];
    CHECK(gaudit_distro_info_version(DATA "/distro-info.csv", "questing-updates", ver, sizeof ver)
          && strcmp(ver, "25.10") == 0);
    CHECK(gaudit_distro_info_version(DATA "/distro-info.csv", "resolute", ver, sizeof ver)
          && strcmp(ver, "26.04") == 0);
    CHECK(!gaudit_distro_info_version(DATA "/distro-info.csv", "nosuch", ver, sizeof ver));
    CHECK(!gaudit_distro_info_version(DATA "/no-such.csv", "questing", ver, sizeof ver));
    /* The switched-off sources with the suite each was for. */
    gaudit_apt_off_source off_list[8];
    size_t n_off = 0;
    CHECK(gaudit_apt_upgrade_disabled_list(DATA "/upgraded/sources.list.d", off_list, 8, &n_off)
          == GAUDIT_BACKEND_OK && n_off == 2);
    for (size_t i = 0; i < n_off; i++)
        CHECK((strcmp(off_list[i].label, "ppa:cappelikan/ppa") == 0 && strcmp(off_list[i].suite, "questing") == 0)
              || (strcmp(off_list[i].label, "legacy.example.org") == 0 && strcmp(off_list[i].suite, "stable") == 0));


    /* Set up again since: add-apt-repository made a file for the new
     * release and left the old one off, so the PPA is no longer switched
     * off. One not set up again still is; a .save copy that is on counts
     * for nothing. */
    CHECK(gaudit_apt_upgrade_disabled_list(DATA "/readded/sources.list.d", off_list, 8, &n_off)
          == GAUDIT_BACKEND_OK && n_off == 1 && strcmp(off_list[0].label, "ppa:other/tools") == 0
          && strcmp(off_list[0].suite, "resolute") == 0);
    CHECK(gaudit_apt_upgrade_disabled_sources(DATA "/readded/sources.list.d", &off, off_names,
                                              sizeof off_names) == GAUDIT_BACKEND_OK
          && off == 1 && strcmp(off_names, "ppa:other/tools") == 0);

    return failures ? 1 : 0;
}
