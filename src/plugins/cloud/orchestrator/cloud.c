/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cloud-mode.h"

#include "cloud-folders.h"
#include "cloud.h"
#include "secret-scan.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
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

/* --- Secrets in the cloud folders kept on this computer -------------------- */

typedef struct {
    FILE *out;
    const char *home;
    const char *folder;      /* absolute */
    const char *service;
    unsigned found, sent;
} secret_ctx;

static void on_secret(const gaudit_secret_hit *hit, void *data)
{
    secret_ctx *c = data;
    c->found++;
    if (c->sent >= GAUDIT_CLOUD_SECRETS_MAX)
        return;
    char abs[2048];
    snprintf(abs, sizeof abs, "%s/%s", c->folder, hit->rel);
    gaudit_cloud_secret_line l = { .by_name = 0 };
    snprintf(l.service, sizeof l.service, "%s", c->service);
    snprintf(l.reason, sizeof l.reason, "%s", hit->reason);
    shown(c->home, abs, l.path, sizeof l.path);
    char buf[2048];
    /* A name cut short would point at another file: left out of the list. */
    if (strlen(abs) - strlen(c->home) + 1 < sizeof l.path
        && gaudit_cloud_format_secret(&l, buf, sizeof buf) == 0 && fputs(buf, c->out) >= 0)
        c->sent++;
}

/* Every folder a client keeps in step on this computer, by its settings or
 * its default, searched as the private files are; never one on another
 * filesystem than the home folder, since listing it may fetch it over the
 * network (rclone and pCloud mounts are such, and are left out). */
static void search_secrets(const char *home, const gaudit_cloud_findings *s, FILE *out)
{
    struct stat hs;
    if (stat(home, &hs) != 0)
        return;
    secret_ctx c = { .out = out, .home = home };
    gaudit_cloud_secret_scan_line sum = { 0 };
    for (unsigned i = 0; i < s->n && sum.folders < 100; i++) {
        const gaudit_cloud_finding *f = &s->f[i];
        struct stat fs;
        if ((f->how != GAUDIT_CLOUD_FOLDER && f->how != GAUDIT_CLOUD_DEFAULT) || f->path[0] != '/'
            || lstat(f->path, &fs) != 0 || !S_ISDIR(fs.st_mode) || fs.st_dev != hs.st_dev)
            continue;
        /* A folder inside one already searched is searched with it. */
        int inside = 0;
        for (unsigned k = 0; k < i && !inside; k++) {
            size_t n = strlen(s->f[k].path);
            inside = n > 0 && strncmp(f->path, s->f[k].path, n) == 0
                     && (f->path[n] == '/' || f->path[n] == '\0')
                     && (s->f[k].how == GAUDIT_CLOUD_FOLDER || s->f[k].how == GAUDIT_CLOUD_DEFAULT);
        }
        if (inside)
            continue;
        c.folder = f->path;
        c.service = f->service;
        gaudit_secret_stats st;
        if (gaudit_secret_scan_area(f->path, getuid(), on_secret, &c, &st) == 0) {
            sum.folders++;
            sum.truncated |= st.truncated;
        }
    }
    sum.found = c.found;
    sum.more = c.found > c.sent;
    char buf[256];
    if (gaudit_cloud_format_secret_scan(&sum, buf, sizeof buf) == 0)
        fputs(buf, out);
}

int gaudit_cloud_collect(const char *home, const char *mounts, const char *root, int full,
                         FILE *out)
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
    if (full)
        search_secrets(home, &s, out);
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
int gaudit_cloud_write_unit(const char *home, const char *service, const char *disk,
                            const char *remote, const char *gathering, const char *lang,
                            char *result, size_t len)
{
    const gaudit_cloud_setup_service *s = gaudit_cloud_setup_find(service);
    const gaudit_cloud_language *l = gaudit_cloud_language_by_code(lang);
    int d = gaudit_cloud_disk_parse(disk);
    char text[4096], name[96], path[1024], folder[128];
    /* Only a gathering folder and words from the program's own table. */
    if (s != NULL && l != NULL && d >= 0)
        gaudit_cloud_folder_name(s, (gaudit_cloud_disk)d, l->private_word, l->shared_word, folder,
                                 sizeof folder);
    if (s == NULL || l == NULL || d < 0 || !gaudit_cloud_gathering_known(gathering)
        || gaudit_cloud_unit_text(s, (gaudit_cloud_disk)d, remote, gathering, folder, text,
                                  sizeof text) != 0) {
        snprintf(result, len, "refused");
        return 2;
    }
    gaudit_cloud_unit_name(s, (gaudit_cloud_disk)d, name, sizeof name);
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

/* A folder name rclone's filter takes as it is: letters, digits, space and
 * ._-/, so nothing in it is a pattern. */
static int plain_under(const char *u)
{
    if (u[0] == '\0' || strlen(u) > 100)
        return 0;
    for (const unsigned char *c = (const unsigned char *)u; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9')
              || *c == ' ' || *c == '.' || *c == '_' || *c == '-' || *c == '/'))
            return 0;
    return strstr(u, "..") == NULL;
}

/* Runs rclone (argv, its path first) with an environment of HOME and
 * LC_ALL=C, stdin and stderr on /dev/null, at most timeout_ms; each line
 * of its output to fn (lines over 1 KiB cut, never kept), which returns 1
 * to stop it. 0 when it ended well or fn stopped it, -1 otherwise
 * (*timed_out set when the time ran out). */
typedef int (*rclone_line_fn)(const char *line, void *ctx);

static int run_rclone(const char *home, char *const argv[], long timeout_ms, rclone_line_fn fn,
                      void *ctx, int *timed_out)
{
    *timed_out = 0;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        /* rclone finds its settings, and its login, from HOME. */
        char env_home[1100];
        snprintf(env_home, sizeof env_home, "HOME=%s", home);
        char *const env[] = { env_home, (char *)"LC_ALL=C", NULL };
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || null < 0 || dup2(null, STDIN_FILENO) < 0
            || dup2(fds[1], STDOUT_FILENO) < 0 || dup2(null, STDERR_FILENO) < 0 || chdir("/") != 0)
            _exit(126);
        execve(argv[0], argv, env);
        _exit(127);
    }
    close(fds[1]);
    static char line[1024];
    size_t used = 0;
    int stopped = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!stopped) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = timeout_ms - (long)((now.tv_sec - start.tv_sec) * 1000
                                        + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) {
            kill(pid, SIGKILL);
            *timed_out = 1;
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        if (poll(&pfd, 1, (int)left) <= 0)
            continue;
        char chunk[4096];
        ssize_t n = read(fds[0], chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        for (ssize_t i = 0; i < n && !stopped; i++) {
            if (chunk[i] != '\n') {
                if (used < sizeof line - 1)
                    line[used++] = chunk[i];
                continue;
            }
            line[used] = '\0';
            if (used > 0 && fn(line, ctx))
                stopped = 1;
            used = 0;
        }
        if (stopped)
            kill(pid, SIGKILL);  /* enough */
    }
    memset(line, 0, sizeof line);  /* no name is kept */
    close(fds[0]);
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    if (stopped)
        return 0;
    return !*timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

typedef struct {
    const char *skip;
    unsigned count;
    int more;
} count_ctx;

static int on_count(const char *line, void *data)
{
    count_ctx *c = data;
    if (strcmp(line, c->skip) == 0)
        return 0;
    if (c->count < GAUDIT_CLOUD_PLAIN_MAX) {
        c->count++;
        return 0;
    }
    c->more = 1;
    return 1;
}

/* The rclone finding for remote that the collection itself finds, or NULL. */
static const gaudit_cloud_finding *rclone_remote(const char *home, const char *mounts,
                                                 const char *remote, gaudit_cloud_findings *s)
{
    gaudit_cloud_where w = { .home = home, .mounts = mounts };
    if (!gaudit_cloud_plain_remote(remote) || gaudit_cloud_find(&w, s) != 0)
        return NULL;
    for (unsigned i = 0; i < s->n; i++)
        if (strcmp(s->f[i].client, "rclone") == 0 && strcmp(s->f[i].name, remote) == 0)
            return &s->f[i];
    return NULL;
}

int gaudit_cloud_plain(const char *home, const char *mounts, const char *remote,
                       const char *rclone, FILE *out)
{
    /* Only a remote the collection itself finds, with an encryption over it. */
    static gaudit_cloud_findings s;
    const gaudit_cloud_finding *f = rclone_remote(home, mounts, remote, &s);
    if (f == NULL || !f->encrypted)
        return 1;
    gaudit_cloud_plain_line p = { 0 };
    snprintf(p.remote, sizeof p.remote, "%s", remote);
    if (f->under[0] == '\0') {
        p.status = 2;  /* the whole remote encrypted: nothing to tell apart */
    } else if (!plain_under(f->under)) {
        p.status = 1;
    } else {
        char target[160], exclude[160], skip[160];
        snprintf(target, sizeof target, "%s:", remote);
        snprintf(exclude, sizeof exclude, "/%s/**", f->under);
        /* lsf names a folder with a slash after it. With the encrypted
         * folder deeper ("a/b"), its top folder is left out of the count
         * too: one level is all that is looked at. */
        size_t top = strcspn(f->under, "/");
        snprintf(skip, sizeof skip, "%.*s/", (int)top, f->under);
        const char *bin = rclone != NULL ? rclone : "/usr/bin/rclone";
        char *const argv[] = { (char *)bin, (char *)"lsf", (char *)"--max-depth", (char *)"1",
                               (char *)"--exclude", exclude, target, NULL };
        count_ctx c = { .skip = skip };
        int timed_out;
        p.status = run_rclone(home, argv, 60000, on_count, &c, &timed_out) == 0 ? 0 : 1;
        p.count = p.status == 0 ? c.count : 0;
        p.more = p.status == 0 ? c.more : 0;
    }
    char buf[512];
    if (gaudit_cloud_format_plain(&p, buf, sizeof buf) != 0 || fputs(buf, out) < 0)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* --- Secrets at a remote, by their names, on a click -------------------------- */

typedef struct {
    FILE *out;
    const char *remote;
    const char *service;
    gaudit_cloud_names_line sum;
    unsigned sent;
} names_ctx;

static int on_name(const char *line, void *data)
{
    names_ctx *c = data;
    if (c->sum.looked >= GAUDIT_CLOUD_NAMES_MAX) {
        c->sum.truncated = 1;
        return 1;
    }
    c->sum.looked++;
    const char *reason = gaudit_secret_reason_by_name(line, 1);
    if (reason == NULL)
        return 0;
    c->sum.found++;
    gaudit_cloud_secret_line l = { .by_name = gaudit_secret_reason_by_name(line, 0) == NULL };
    if (c->sent >= GAUDIT_CLOUD_SECRETS_MAX || strlen(line) >= sizeof l.path)
        return 0;
    snprintf(l.service, sizeof l.service, "%s", c->service);
    snprintf(l.remote, sizeof l.remote, "%s", c->remote);
    snprintf(l.path, sizeof l.path, "%s", line);
    snprintf(l.reason, sizeof l.reason, "%s", reason);
    char buf[2048];
    if (gaudit_cloud_format_secret(&l, buf, sizeof buf) == 0 && fputs(buf, c->out) >= 0)
        c->sent++;
    return 0;
}

int gaudit_cloud_names(const char *home, const char *mounts, const char *remote,
                       const char *rclone, FILE *out)
{
    static gaudit_cloud_findings s;
    const gaudit_cloud_finding *f = rclone_remote(home, mounts, remote, &s);
    if (f == NULL)
        return 1;
    names_ctx c = { .out = out, .remote = remote, .service = f->service };
    snprintf(c.sum.remote, sizeof c.sum.remote, "%s", remote);
    /* Outside the encrypted folder only: what is in it is encrypted. A
     * crypt over the whole remote leaves nothing outside to look at. */
    if (f->encrypted && (f->under[0] == '\0' || !plain_under(f->under))) {
        c.sum.status = f->under[0] == '\0' ? 0 : 1;
    } else {
        char target[160], exclude[160];
        snprintf(target, sizeof target, "%s:", remote);
        snprintf(exclude, sizeof exclude, "/%s/**", f->under);
        const char *bin = rclone != NULL ? rclone : "/usr/bin/rclone";
        char *const with[] = { (char *)bin, (char *)"lsf", (char *)"-R", (char *)"--files-only",
                               (char *)"--exclude", exclude, target, NULL };
        char *const without[] = { (char *)bin, (char *)"lsf", (char *)"-R", (char *)"--files-only",
                                  target, NULL };
        int timed_out;
        int r = run_rclone(home, f->encrypted ? with : without, 300000, on_name, &c, &timed_out);
        c.sum.status = r == 0 || timed_out ? 0 : 1;
        c.sum.truncated |= timed_out;
    }
    c.sum.more = c.sum.found > c.sent;
    char buf[512];
    if (gaudit_cloud_format_names(&c.sum, buf, sizeof buf) != 0 || fputs(buf, out) < 0)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

int gaudit_cloud_mode(int argc, char *argv[])
{
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/')
        return 1;
    if (argc == 3 && (strcmp(argv[2], "quick") == 0 || strcmp(argv[2], "full") == 0))
        return gaudit_cloud_collect(pw->pw_dir, NULL, NULL, strcmp(argv[2], "full") == 0, stdout);
    if (argc == 4 && strcmp(argv[2], "names") == 0)
        return gaudit_cloud_names(pw->pw_dir, NULL, argv[3], NULL, stdout);
    if (argc == 4 && strcmp(argv[2], "plain") == 0)
        return gaudit_cloud_plain(pw->pw_dir, NULL, argv[3], NULL, stdout);
    if (argc == 8 && strcmp(argv[2], "unit") == 0) {
        char result[16];
        gaudit_cloud_write_unit(pw->pw_dir, argv[3], argv[4], argv[5], argv[6], argv[7], result,
                                sizeof result);
        printf("(cloud-unit-written (result \"%s\"))\n", result);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    return 2;
}
