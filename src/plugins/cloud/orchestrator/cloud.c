/* SPDX-License-Identifier: GPL-3.0-only */
#include "cloud-mode.h"

#include "cloud-folders.h"
#include "cloud.h"

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* "~/..." in the home folder, else as it is. */
static void shown(const char *home, const char *path, char *out, size_t len)
{
    size_t hl = strlen(home);
    if (path[0] != '\0' && strncmp(path, home, hl) == 0 && path[hl] == '/')
        snprintf(out, len, "~%.*s", (int)(len - 2), path + hl);
    else
        snprintf(out, len, "%.*s", (int)(len - 1), path);
}

int gaudit_cloud_collect(const char *home, const char *mounts, const char *root, FILE *out)
{
    gaudit_cloud_where w = { .home = home, .mounts = mounts, .root = root };
    gaudit_cloud_findings s;
    if (gaudit_cloud_find(&w, &s) != 0)
        return 1;
    char buf[2048];
    unsigned count = 0;
    for (unsigned i = 0; i < s.n; i++) {
        const gaudit_cloud_finding *f = &s.f[i];
        gaudit_cloud_line l = { .how = (int)f->how, .encrypted = f->encrypted,
                                .gathered = f->gathered };
        snprintf(l.client, sizeof l.client, "%s", f->client);
        snprintf(l.service, sizeof l.service, "%s", f->service);
        shown(home, f->path, l.path, sizeof l.path);
        snprintf(l.name, sizeof l.name, "%s", f->name);
        if (gaudit_cloud_format_folder(&l, buf, sizeof buf) == 0 && fputs(buf, out) >= 0)
            count++;
    }
    gaudit_cloud_end e = { .count = count, .more = s.more, .gatherings = s.gathering_count,
                           .rclone_unreadable = s.rclone_unreadable };
    shown(home, s.gathering, e.gathering, sizeof e.gathering);
    if (gaudit_cloud_format_end(&e, buf, sizeof buf) != 0 || fputs(buf, out) < 0)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

int gaudit_cloud_mode(int argc, char *argv[])
{
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/')
        return 1;
    if (argc == 3 && (strcmp(argv[2], "quick") == 0 || strcmp(argv[2], "full") == 0))
        return gaudit_cloud_collect(pw->pw_dir, NULL, NULL, stdout);
    return 2;
}
