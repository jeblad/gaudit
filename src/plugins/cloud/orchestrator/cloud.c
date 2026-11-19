/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cloud-mode.h"

#include "cloud-folders.h"
#include "cloud.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
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
        snprintf(l.via, sizeof l.via, "%s", f->via);
        if (gaudit_cloud_format_folder(&l, buf, sizeof buf) == 0 && fputs(buf, out) >= 0)
            count++;
    }
    for (unsigned i = 0; i < s.n_units; i++) {
        gaudit_cloud_unit_line u = { .enabled = s.units[i].enabled, .mounted = s.units[i].mounted };
        snprintf(u.file, sizeof u.file, "%s", s.units[i].file);
        shown(home, s.units[i].path, u.path, sizeof u.path);
        if (gaudit_cloud_format_unit(&u, buf, sizeof buf) == 0)
            fputs(buf, out);
    }
    gaudit_cloud_end e = { .count = count, .more = s.more, .gatherings = s.gathering_count,
                           .rclone_unreadable = s.rclone_unreadable };
    shown(home, s.gathering, e.gathering, sizeof e.gathering);
    if (gaudit_cloud_format_end(&e, buf, sizeof buf) != 0 || fputs(buf, out) < 0)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* Writes the unit for service and remote, as the user, only on the user's
 * informed choice (the page showed the very text and asked): a new file,
 * or the same text again; never over another file, never through a link. */
int gaudit_cloud_write_unit(const char *home, const char *service, const char *remote,
                            char *result, size_t len)
{
    const gaudit_cloud_setup_service *s = gaudit_cloud_setup_find(service);
    char text[4096], name[64], path[1024];
    if (s == NULL || gaudit_cloud_unit_text(s, remote, text, sizeof text) != 0) {
        snprintf(result, len, "refused");
        return 2;
    }
    gaudit_cloud_unit_name(s, name, sizeof name);
    const char *parts[] = { ".config", "systemd", "user" };
    int dir = open(home, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    for (size_t i = 0; dir >= 0 && i < 3; i++) {
        if (mkdirat(dir, parts[i], 0755) != 0 && errno != EEXIST) {
            close(dir);
            dir = -1;
            break;
        }
        int next = openat(dir, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dir);
        dir = next;
    }
    if (dir < 0) {
        snprintf(result, len, "error");
        return 1;
    }
    snprintf(path, sizeof path, "%s", name);
    int fd = openat(dir, path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0 && errno == EEXIST) {
        /* There already: the same text is fine, anything else is not ours to change. */
        int rfd = openat(dir, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        char have[4096];
        ssize_t got = rfd >= 0 ? read(rfd, have, sizeof have - 1) : -1;
        if (rfd >= 0)
            close(rfd);
        close(dir);
        if (got >= 0) {
            have[got] = '\0';
            snprintf(result, len, "%s", strcmp(have, text) == 0 ? "unchanged" : "foreign");
            return strcmp(have, text) == 0 ? 0 : 1;
        }
        snprintf(result, len, "error");
        return 1;
    }
    close(dir);
    if (fd < 0) {
        snprintf(result, len, "error");
        return 1;
    }
    size_t want = strlen(text);
    int ok = write(fd, text, want) == (ssize_t)want && fsync(fd) == 0;
    close(fd);
    snprintf(result, len, "%s", ok ? "written" : "error");
    return ok ? 0 : 1;
}

int gaudit_cloud_mode(int argc, char *argv[])
{
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/')
        return 1;
    if (argc == 3 && (strcmp(argv[2], "quick") == 0 || strcmp(argv[2], "full") == 0))
        return gaudit_cloud_collect(pw->pw_dir, NULL, NULL, stdout);
    if (argc == 5 && strcmp(argv[2], "unit") == 0) {
        char result[16];
        gaudit_cloud_write_unit(pw->pw_dir, argv[3], argv[4], result, sizeof result);
        printf("(cloud-unit-written (result \"%s\"))\n", result);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    return 2;
}
