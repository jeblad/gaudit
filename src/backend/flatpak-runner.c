/* SPDX-License-Identifier: GPL-3.0-only */
#include "flatpak-runner.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_OUTPUT 4096
#define MAX_VALUE  1000000UL

/* --- Parser --------------------------------------------------------------- */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

int gaudit_flatpak_parse(const char *text, gaudit_flatpak_state *out)
{
    if (text == NULL || out == NULL)
        return -1;

    gaudit_flatpak_state st = { 0 };
    unsigned seen = 0;
    const char *p = skip_ws(text);

    if (strncmp(p, "(flatpak", 8) != 0)
        return -1;
    p += 8;
    if (*p != ' ' && *p != '\t' && *p != '\n' && *p != ')')
        return -1;

    for (;;) {
        p = skip_ws(p);
        if (*p == ')') {
            p++;
            break;
        }
        if (*p != '(')
            return -1;
        p++;

        char key[32];
        size_t n = 0;
        while ((*p >= 'a' && *p <= 'z') || *p == '-') {
            if (n + 1 >= sizeof key)
                return -1;
            key[n++] = *p++;
        }
        key[n] = '\0';
        if (n == 0 || (*p != ' ' && *p != '\t'))
            return -1;
        p = skip_ws(p);
        if (!isdigit((unsigned char)*p))
            return -1;
        unsigned long v = 0;
        while (isdigit((unsigned char)*p)) {
            v = v * 10 + (unsigned long)(*p - '0');
            if (v > MAX_VALUE)
                return -1;
            p++;
        }
        p = skip_ws(p);
        if (*p != ')')
            return -1;
        p++;

        unsigned *dst;
        unsigned bit;
        if (strcmp(key, "apps") == 0) {
            dst = &st.apps;
            bit = 1;
        } else if (strcmp(key, "eol-apps") == 0) {
            dst = &st.eol_apps;
            bit = 2;
        } else if (strcmp(key, "eol-unused") == 0) {
            dst = &st.eol_unused;
            bit = 4;
        } else if (strcmp(key, "eol-pinned") == 0) {
            dst = &st.eol_pinned;
            bit = 8;
        } else {
            return -1;
        }
        if (seen & bit)
            return -1;
        seen |= bit;
        *dst = (unsigned)v;
    }

    if (*skip_ws(p) != '\0' || seen != 15 || st.eol_apps > st.apps)
        return -1;
    *out = st;
    return 0;
}

/* --- Runner --------------------------------------------------------------- */

static long elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

gaudit_backend_status gaudit_flatpak_run_probe(const char *flatpak_bin, const char *probe_path,
                                               int timeout_ms, gaudit_flatpak_state *out)
{
    if (flatpak_bin == NULL || probe_path == NULL || out == NULL || timeout_ms <= 0)
        return GAUDIT_BACKEND_ERROR;
    if (access(flatpak_bin, X_OK) != 0)
        return GAUDIT_BACKEND_UNAVAILABLE;
    if (access(probe_path, X_OK) != 0)
        return GAUDIT_BACKEND_NOT_IMPLEMENTED;

    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL)
        return GAUDIT_BACKEND_ERROR;
    char home[PATH_MAX + 8];
    int hn = snprintf(home, sizeof home, "HOME=%s", pw->pw_dir);
    if (hn < 0 || (size_t)hn >= sizeof home)
        return GAUDIT_BACKEND_ERROR;
    char *const envp[] = { home, NULL };
    char *const argv[] = { (char *)probe_path, NULL };

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return GAUDIT_BACKEND_ERROR;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    pid_t pid;
    int rc = posix_spawn(&pid, probe_path, &actions, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        return rc == ENOENT ? GAUDIT_BACKEND_NOT_IMPLEMENTED : GAUDIT_BACKEND_ERROR;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char buf[MAX_OUTPUT + 1];
    size_t len = 0;
    int failed = 0;

    for (;;) {
        long left = timeout_ms - elapsed_ms(&start);
        if (left <= 0) {
            failed = 1;
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        int pr = poll(&pfd, 1, (int)left);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0) {
            failed = 1;
            break;
        }
        ssize_t n = read(fds[0], buf + len, sizeof buf - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            failed = 1;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
        if (len >= MAX_OUTPUT) {
            failed = 1;  /* more than any valid answer */
            break;
        }
    }
    close(fds[0]);

    /* Reap the child. It may have closed stdout but still be running, so the
     * timeout applies here too. */
    if (failed)
        kill(pid, SIGKILL);
    int status = 0;
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            break;
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return GAUDIT_BACKEND_ERROR;
        }
        if (!failed && elapsed_ms(&start) >= timeout_ms) {
            failed = 1;
            kill(pid, SIGKILL);
        }
        struct timespec pause = { 0, 10 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    if (failed)
        return GAUDIT_BACKEND_ERROR;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
        return GAUDIT_BACKEND_MISSING_DEPENDENCY;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return GAUDIT_BACKEND_ERROR;

    buf[len] = '\0';
    return gaudit_flatpak_parse(buf, out) == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
