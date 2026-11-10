/* SPDX-License-Identifier: GPL-3.0-only */
/* Fedora backend files: detection, metadata cache age and automatic updates.
 * Trees are built at run time under the build directory, because git does
 * not keep file modes and mtimes reliably. */
#include "dnf-files.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

static char base[1024];  /* well below PATH_MAX, so base + rel always fits */

/* mkdir -p for base/rel. */
static void mkdirs(const char *rel)
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    for (char *p = path + strlen(base) + 1; *p != '\0'; p++)
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    mkdir(path, 0755);
}

/* Write base/rel with content, mode and (if mtime != 0) mtime. */
static void put(const char *rel, const char *content, mode_t mode, time_t mtime)
{
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", base, rel);
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", rel);
    char *slash = strrchr(dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        mkdirs(dir);
    }
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
    chmod(path, mode);
    if (mtime != 0) {
        struct timespec times[2] = { { mtime, 0 }, { mtime, 0 } };
        utimensat(AT_FDCWD, path, times, 0);
    }
}

static const char *root(const char *name)
{
    static char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", base, name);
    return path;
}

int main(void)
{
    snprintf(base, sizeof base, "%s/fedora-XXXXXX", GAUDIT_TEST_TMP_DIR);
    mkdir(GAUDIT_TEST_TMP_DIR, 0755);
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    /* Detection. */
    put("ok/usr/lib/sysimage/rpm/rpmdb.sqlite", "x", 0644, 0);
    put("ok/usr/bin/rpm", "#!/bin/sh\n", 0755, 0);
    put("ok/usr/bin/dnf5", "#!/bin/sh\n", 0755, 0);
    CHECK(gaudit_fedora_present(root("ok")) == 1);

    put("rhel/var/lib/rpm/rpmdb.sqlite", "x", 0644, 0);   /* rpm + dnf4, no dnf5 */
    put("rhel/usr/bin/rpm", "#!/bin/sh\n", 0755, 0);
    put("rhel/usr/bin/dnf", "#!/bin/sh\n", 0755, 0);
    CHECK(gaudit_fedora_present(root("rhel")) == 0);

    put("noexec/usr/lib/sysimage/rpm/rpmdb.sqlite", "x", 0644, 0);
    put("noexec/usr/bin/rpm", "#!/bin/sh\n", 0755, 0);
    put("noexec/usr/bin/dnf5", "#!/bin/sh\n", 0644, 0);   /* not executable */
    CHECK(gaudit_fedora_present(root("noexec")) == 0);
    CHECK(gaudit_fedora_present(root("missing")) == 0);

    /* Metadata cache: the newest repomd.xml wins; other files do not count. */
    time_t now = time(NULL);
    int64_t t = 0;
    put("cache/fedora-1234/repodata/repomd.xml", "<repomd/>", 0644, now - 3 * 86400);
    put("cache/updates-5678/repodata/repomd.xml", "<repomd/>", 0644, now - 86400);
    put("cache/updates-5678/repodata/other.xml", "x", 0644, now);
    CHECK(gaudit_dnf_cache_time(root("cache"), &t) == GAUDIT_BACKEND_OK);
    CHECK(t == (int64_t)(now - 86400));
    mkdirs("empty-cache/fedora-1234");
    CHECK(gaudit_dnf_cache_time(root("empty-cache"), &t) == GAUDIT_BACKEND_UNAVAILABLE);
    CHECK(gaudit_dnf_cache_time(root("no-cache"), &t) == GAUDIT_BACKEND_UNAVAILABLE);

    /* Automatic updates. */
    int on = -1;
    const char *timer = "etc/systemd/system/timers.target.wants/dnf5-automatic.timer";
    char rel[PATH_MAX];

    CHECK(gaudit_dnf_automatic(root("auto-none"), &on) == GAUDIT_BACKEND_OK && on == 0);  /* no timer */

    snprintf(rel, sizeof rel, "auto-on/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-on/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-on"), &on) == GAUDIT_BACKEND_OK && on == 1);

    snprintf(rel, sizeof rel, "auto-download/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-download/etc/dnf/automatic.conf",
        "[commands]\ndownload_updates = yes\napply_updates = no\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-download"), &on) == GAUDIT_BACKEND_OK && on == 0);

    /* No /etc override: the packaged default decides. */
    snprintf(rel, sizeof rel, "auto-default/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-default/usr/share/dnf5/dnf5-plugins/automatic.conf",
        "[commands]\n# apply_updates = no\napply_updates=True\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-default"), &on) == GAUDIT_BACKEND_OK && on == 1);

    /* The key in another section does not count; absent means no. */
    snprintf(rel, sizeof rel, "auto-section/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-section/etc/dnf/automatic.conf", "[emitters]\napply_updates = yes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-section"), &on) == GAUDIT_BACKEND_OK && on == 0);

    /* The alias name of the timer counts too. */
    put("auto-alias/etc/systemd/system/timers.target.wants/dnf-automatic.timer", "", 0644, 0);
    put("auto-alias/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-alias"), &on) == GAUDIT_BACKEND_OK && on == 1);

    /* The other override file alone. */
    snprintf(rel, sizeof rel, "auto-plugin-dir/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-plugin-dir/etc/dnf/dnf5-plugins/automatic.conf", "[commands]\napply_updates = yes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-plugin-dir"), &on) == GAUDIT_BACKEND_OK && on == 1);

    /* Both override files, agreeing and disagreeing. */
    snprintf(rel, sizeof rel, "auto-agree/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-agree/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n", 0644, 0);
    put("auto-agree/etc/dnf/dnf5-plugins/automatic.conf", "[commands]\napply_updates = true\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-agree"), &on) == GAUDIT_BACKEND_OK && on == 1);
    snprintf(rel, sizeof rel, "auto-conflict/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-conflict/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n", 0644, 0);
    put("auto-conflict/etc/dnf/dnf5-plugins/automatic.conf", "[commands]\napply_updates = no\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-conflict"), &on) == GAUDIT_BACKEND_ERROR);

    /* As shipped: timer enabled, packaged default only (downloads, no apply). */
    snprintf(rel, sizeof rel, "auto-shipped/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-shipped/usr/share/dnf5/dnf5-plugins/automatic.conf",
        "[commands]\napply_updates = no\ndownload_updates = yes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-shipped"), &on) == GAUDIT_BACKEND_OK && on == 0);

    /* A value we do not understand: no guess. */
    snprintf(rel, sizeof rel, "auto-odd/%s", timer);
    put(rel, "", 0644, 0);
    put("auto-odd/etc/dnf/automatic.conf", "[commands]\napply_updates = sometimes\n", 0644, 0);
    CHECK(gaudit_dnf_automatic(root("auto-odd"), &on) == GAUDIT_BACKEND_ERROR);

    if (failures)
        fprintf(stderr, "%d check(s) failed (fixtures in %s)\n", failures, base);
    return failures ? 1 : 0;
}
