/* SPDX-License-Identifier: GPL-3.0-only */
/* The GUI's environment: which variables are taken out, and that a start
 * with them starts again without them, keeping the rest and knowing what
 * was removed. The test starts itself again, as the GUI does. */
#define _DEFAULT_SOURCE
#include "gaudit-environ.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        /* Who can change a path. */
        gaudit_env_judgement j;
        gaudit_environ_judge_path("/usr/lib", &j);
        CHECK(j.reach == GAUDIT_ENV_ROOT_ONLY);
        gaudit_environ_judge_path("/usr/lib/no-such-folder/deeper", &j);
        CHECK(j.reach == GAUDIT_ENV_ROOT_ONLY);       /* only root can make it */
        gaudit_environ_judge_path("/tmp", &j);
        CHECK(j.reach == GAUDIT_ENV_OTHERS);           /* every account writes there */
        gaudit_environ_judge_path("", &j);
        CHECK(j.reach == GAUDIT_ENV_EMPTY);            /* the folder it is started in */
        gaudit_environ_judge_path("lib", &j);
        CHECK(j.reach == GAUDIT_ENV_RELATIVE);
        char dir[] = "/tmp/gaudit-environ-XXXXXX";
        if (geteuid() != 0 && mkdtemp(dir) != NULL) {
            chmod(dir, 0755);
            char sub[300], link[300];
            snprintf(sub, sizeof sub, "%s/not-yet", dir);
            gaudit_environ_judge_path(sub, &j);
            CHECK(j.reach == GAUDIT_ENV_OTHERS || j.reach == GAUDIT_ENV_OWNER);  /* /tmp, or the user's */
            /* A link the user owns the folder of, leading to the system's
             * folder: the folder it sits in decides, the user can swap it. */
            snprintf(link, sizeof link, "%s/lib", dir);
            CHECK(symlink("/usr/lib", link) == 0);
            gaudit_environ_judge_path(link, &j);
            CHECK(j.reach != GAUDIT_ENV_ROOT_ONLY);
            unlink(link);
            rmdir(dir);
        }
        CHECK(gaudit_environ_kind("LD_LIBRARY_PATH") == GAUDIT_ENV_PATHS);
        CHECK(gaudit_environ_kind("LD_PRELOAD") == GAUDIT_ENV_PATHS);
        CHECK(gaudit_environ_kind("GTK_MODULES") == GAUDIT_ENV_MODULES);
        CHECK(gaudit_environ_kind("LD_DEBUG") == GAUDIT_ENV_OTHER);
        if (failures > 0)
            return 1;
        /* The first start: some unwanted, some not; and an entry the caller
         * made up, which must not reach the new start. Does not return. */
        setenv("GAUDIT_REMOVED_0", "LD_PRELOAD=/made/up.so", 1);
        setenv("LD_LIBRARY_PATH", "/usr/local/cuda/lib64:", 1);
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
    CHECK(getenv("GAUDIT_REMOVED_0") == NULL && getenv("LD_LIBRARY_PATH") == NULL);
    /* The values came along, and only those the first start removed. */
    int cuda = 0;
    for (size_t i = 0; i < gaudit_environ_removed_count(); i++) {
        const char *e = gaudit_environ_removed_entry(i);
        CHECK(strstr(e, "/made/up.so") == NULL);
        cuda += strcmp(e, "LD_LIBRARY_PATH=/usr/local/cuda/lib64:") == 0;
    }
    CHECK(cuda == 1 && gaudit_environ_removed_count() == 3);
    if (failures == 0)
        puts("environ: all checks passed");
    return failures == 0 ? 0 : 1;
}
