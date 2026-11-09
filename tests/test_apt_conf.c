/* SPDX-License-Identifier: GPL-3.0-only */
/* The apt.conf reader on fixtures in tests/data/apt-conf/<case>/. */
#include "apt-conf.h"

#include <stdio.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* Returns the status; *enabled is -1 unless the reader set it. */
static gaudit_backend_status read_case(const char *name, int *enabled)
{
    char conf_file[512], conf_dir[512];
    snprintf(conf_file, sizeof conf_file, "%s/%s/apt.conf", GAUDIT_TEST_DATA_DIR "/apt-conf", name);
    snprintf(conf_dir, sizeof conf_dir, "%s/%s/apt.conf.d", GAUDIT_TEST_DATA_DIR "/apt-conf", name);
    *enabled = -1;
    return gaudit_apt_unattended_upgrade(conf_file, conf_dir, enabled);
}

#define EXPECT(name, status, value)                                     \
    do {                                                                \
        int enabled_;                                                   \
        CHECK(read_case(name, &enabled_) == (status));                  \
        CHECK(enabled_ == (value));                                     \
    } while (0)

int main(void)
{
    EXPECT("enabled",      GAUDIT_BACKEND_OK, 1);
    EXPECT("disabled",     GAUDIT_BACKEND_OK, 0);
    EXPECT("absent",       GAUDIT_BACKEND_OK, 0);   /* apt's default is off */
    EXPECT("override",     GAUDIT_BACKEND_OK, 0);   /* later file wins */
    EXPECT("conf-last",    GAUDIT_BACKEND_OK, 1);   /* apt.conf is read last */
    EXPECT("ignored",      GAUDIT_BACKEND_OK, 0);   /* .disabled, .dpkg-old skipped */
    EXPECT("comment",      GAUDIT_BACKEND_OK, 0);
    EXPECT("options",      GAUDIT_BACKEND_OK, 1);   /* Unattended-Upgrade::* is not the switch */
    EXPECT("nested",       GAUDIT_BACKEND_ERROR, -1);  /* unsupported form: no guess */
    EXPECT("nested-split", GAUDIT_BACKEND_ERROR, -1);
    EXPECT("no-such-case", GAUDIT_BACKEND_OK, 0);   /* nothing configured at all */

    int enabled;
    CHECK(gaudit_apt_unattended_upgrade(NULL, "x", &enabled) == GAUDIT_BACKEND_ERROR);
    CHECK(gaudit_apt_unattended_upgrade("x", "x", NULL) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
