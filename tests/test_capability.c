/* SPDX-License-Identifier: GPL-3.0-only */
/* Capability presence, and the developer builds' switch that pretends a
 * capability is not installed. Uses /bin/sh as an installed program. */
#include "config.h"

#include "gaudit/backend.h"

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

int main(void)
{
    static const char *const sh[] = { "/bin/sh", NULL };
    static const char *const none[] = { "/nonexistent/gaudit-test", NULL };
    const gaudit_capability ufw = { .id = "ufw", .paths = sh, .packages = NULL };
    const gaudit_capability ufw2 = { .id = "ufw2", .paths = sh, .packages = NULL };
    const gaudit_capability missing = { .id = "x", .paths = none, .packages = NULL };

    CHECK(gaudit_capability_present(&ufw));
    CHECK(!gaudit_capability_present(&missing));
    CHECK(!gaudit_capability_present(NULL));

#if GAUDIT_DEVELOPER_BUILD
    CHECK(gaudit_capability_pretended()[0] == '\0');
    CHECK(gaudit_capability_pretend_missing("clamav,ufw") == 0);
    CHECK(!gaudit_capability_present(&ufw));
    CHECK(gaudit_capability_present(&ufw2));   /* whole ids only */
    CHECK(gaudit_capability_pretend_missing("ufw2") == 0);
    CHECK(gaudit_capability_present(&ufw));    /* replaced, not added */
    CHECK(!gaudit_capability_present(&ufw2));

    /* Anything but ids and commas is rejected and leaves the list alone. */
    CHECK(gaudit_capability_pretend_missing("ufw;rm") == -1);
    CHECK(gaudit_capability_pretend_missing("UFW") == -1);
    CHECK(gaudit_capability_pretend_missing(NULL) == -1);
    CHECK(!gaudit_capability_present(&ufw2));
    CHECK(gaudit_capability_pretend_missing("") == 0);
    CHECK(gaudit_capability_present(&ufw2));
#endif

    if (failures == 0)
        puts("capability: all checks passed");
    return failures == 0 ? 0 : 1;
}
