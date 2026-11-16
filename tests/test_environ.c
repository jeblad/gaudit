/* SPDX-License-Identifier: GPL-3.0-only */
/* The GUI's environment: which variables are taken out, and that a start
 * with them starts again without them, keeping the rest and knowing what
 * was removed. The test starts itself again, as the GUI does. */
#define _POSIX_C_SOURCE 200809L
#include "gaudit-environ.h"

#include <stdio.h>
#include <stdlib.h>
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

int main(int argc, char *argv[])
{
    (void)argc;
    if (getenv("GAUDIT_TEST_ENVIRON_AGAIN") == NULL) {
        /* Which are unwanted. */
        CHECK(gaudit_environ_unwanted("LD_PRELOAD=/tmp/x.so"));
        CHECK(gaudit_environ_unwanted("LD_LIBRARY_PATH="));
        CHECK(gaudit_environ_unwanted("GTK_MODULES=foo"));
        CHECK(gaudit_environ_unwanted("GIO_EXTRA_MODULES=/x"));
        CHECK(gaudit_environ_unwanted("GTK_DEBUG=interactive"));
        CHECK(!gaudit_environ_unwanted("GTK_IM_MODULE=ibus"));
        CHECK(!gaudit_environ_unwanted("GTK_MODULESX=1"));
        CHECK(!gaudit_environ_unwanted("HOME=/home/u"));
        CHECK(!gaudit_environ_unwanted("XLD_PRELOAD=1"));
        CHECK(!gaudit_environ_unwanted(NULL));
        if (failures > 0)
            return 1;
        /* The first start: some unwanted, some not. Does not return. */
        setenv("GAUDIT_TEST_ENVIRON_AGAIN", "1", 1);
        setenv("LD_GAUDIT_TEST", "1", 1);
        setenv("GTK_MODULES", "nothing", 1);
        setenv("GTK_IM_MODULE", "ibus", 1);
        gaudit_environ_clean(argv);
        fputs("environ: did not start again\n", stderr);
        return 1;
    }
    /* The second start: without them, the rest kept, and knowing which. */
    gaudit_environ_clean(argv);
    const char *removed = gaudit_environ_removed();
    CHECK(removed != NULL && strstr(removed, "LD_GAUDIT_TEST") != NULL
          && strstr(removed, "GTK_MODULES") != NULL && strstr(removed, "GTK_IM_MODULE") == NULL);
    CHECK(getenv("LD_GAUDIT_TEST") == NULL && getenv("GTK_MODULES") == NULL);
    CHECK(getenv("GTK_IM_MODULE") != NULL && strcmp(getenv("GTK_IM_MODULE"), "ibus") == 0);
    CHECK(getenv("GAUDIT_REMOVED_ENV") == NULL);  /* never passed on */
    if (failures == 0)
        puts("environ: all checks passed");
    return failures == 0 ? 0 : 1;
}
