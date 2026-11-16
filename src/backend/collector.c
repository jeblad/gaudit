/* SPDX-License-Identifier: GPL-3.0-only */
#include "collector.h"

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

#define MAX_FIELDS 16

/* --- Parser --------------------------------------------------------------- */

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

int gaudit_sexpr_parse(const char *text, const char *head,
                       const gaudit_sexpr_field *fields, size_t n_fields)
{
    if (text == NULL || head == NULL || fields == NULL || n_fields == 0 || n_fields > MAX_FIELDS)
        return -1;

    long long values[MAX_FIELDS];
    char texts[MAX_FIELDS][256];
    int seen[MAX_FIELDS] = { 0 };
    const char *p = skip_ws(text);

    if (*p != '(')
        return -1;
    p++;
    size_t head_len = strlen(head);
    if (strncmp(p, head, head_len) != 0)
        return -1;
    p += head_len;
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

        size_t i = 0;
        while (i < n_fields && strcmp(fields[i].key, key) != 0)
            i++;
        if (i == n_fields || seen[i])
            return -1;  /* unknown or repeated key */

        p = skip_ws(p);
        if (fields[i].text != NULL) {
            if (*p != '"' || fields[i].text_len == 0 || fields[i].text_len > sizeof texts[i])
                return -1;
            p++;
            size_t n_out = 0;
            while (*p != '"') {
                unsigned char c = (unsigned char)*p;
                if (c == '\\') {
                    p++;
                    c = (unsigned char)*p;
                    if (c != '"' && c != '\\')
                        return -1;
                } else if (c < 0x20 || c == 0x7f) {
                    return -1;  /* control characters, or the end of the input */
                }
                if (n_out + 1 >= fields[i].text_len)
                    return -1;  /* too long */
                texts[i][n_out++] = (char)c;
                p++;
            }
            texts[i][n_out] = '\0';
            p++;
            p = skip_ws(p);
            if (*p != ')')
                return -1;
            p++;
            seen[i] = 1;
            continue;
        }
        int negative = 0;
        if (*p == '-' && fields[i].min < 0) {
            negative = 1;
            p++;
        }
        if (!isdigit((unsigned char)*p))
            return -1;
        /* v never exceeds its bound before a step, and every bound is far
         * below LLONG_MAX / 10, so v * 10 + digit cannot overflow. */
        long long bound = negative ? -fields[i].min : fields[i].max;
        long long v = 0;
        while (isdigit((unsigned char)*p)) {
            v = v * 10 + (*p - '0');
            if (v > bound)
                return -1;
            p++;
        }
        if (negative)
            v = -v;
        p = skip_ws(p);
        if (*p != ')')
            return -1;
        p++;
        values[i] = v;
        seen[i] = 1;
    }

    if (*skip_ws(p) != '\0')
        return -1;
    for (size_t i = 0; i < n_fields; i++)
        if (!seen[i])
            return -1;
    for (size_t i = 0; i < n_fields; i++) {
        if (fields[i].text != NULL)
            memcpy(fields[i].text, texts[i], strlen(texts[i]) + 1);
        else
            *fields[i].value = values[i];
    }
    return 0;
}

/* --- Runner --------------------------------------------------------------- */

static long elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

gaudit_backend_status gaudit_collector_run(const char *probe_path, int timeout_ms,
                                           char *buf, size_t buf_len)
{
    return gaudit_collector_run_arg(probe_path, NULL, timeout_ms, buf, buf_len);
}

gaudit_backend_status gaudit_collector_run_arg(const char *probe_path, const char *arg,
                                               int timeout_ms, char *buf, size_t buf_len)
{
    if (probe_path == NULL || buf == NULL || buf_len < 2 || timeout_ms <= 0)
        return GAUDIT_BACKEND_ERROR;
    buf[0] = '\0';
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
    char *const argv[] = { (char *)probe_path, (char *)arg, NULL };

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
        ssize_t n = read(fds[0], buf + len, buf_len - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            failed = 1;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
        if (len >= buf_len - 1) {
            failed = 1;  /* more than any valid answer */
            break;
        }
    }
    close(fds[0]);
    buf[len] = '\0';

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
    if (failed) {
        buf[0] = '\0';
        return GAUDIT_BACKEND_ERROR;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
        return GAUDIT_BACKEND_MISSING_DEPENDENCY;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return GAUDIT_BACKEND_ERROR;
    return GAUDIT_BACKEND_OK;
}

/* --- Lists of packages without a source ------------------------------------- */

#define MAX_LIST_LINE 512

gaudit_backend_status gaudit_collector_sourceless(const char *text, gaudit_sourceless_fn fn,
                                                  void *ctx)
{
    if (text == NULL)
        return GAUDIT_BACKEND_ERROR;
    unsigned seen = 0;
    int ended = 0;
    const char *p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        if (nl == NULL || ended)
            return GAUDIT_BACKEND_ERROR;  /* output ending mid-line, or after the end line */
        size_t len = (size_t)(nl - p);
        if (len == 0 || len >= MAX_LIST_LINE)
            return GAUDIT_BACKEND_ERROR;
        char line[MAX_LIST_LINE];
        memcpy(line, p, len);
        line[len] = '\0';
        p = nl + 1;

        long long count;
        const gaudit_sexpr_field end[] = { { .key = "count", .value = &count, .max = 10000000LL } };
        if (gaudit_sexpr_parse(line, "end", end, 1) == 0) {
            if ((unsigned long long)count != seen)
                return GAUDIT_BACKEND_ERROR;
            ended = 1;
            continue;
        }
        char name[128], arch[32], version[96], offered[96];
        long long group;
        const gaudit_sexpr_field pkg[] = {
            { .key = "name",    .text = name,    .text_len = sizeof name },
            { .key = "arch",    .text = arch,    .text_len = sizeof arch },
            { .key = "version", .text = version, .text_len = sizeof version },
            /* Collectors give the first three groups only; KEPT is the
             * Debian backend's own. */
            { .key = "group",   .value = &group, .max = GAUDIT_SOURCELESS_OTHER_SOURCE },
            { .key = "offered", .text = offered, .text_len = sizeof offered },
        };
        if (gaudit_sexpr_parse(line, "package", pkg, sizeof pkg / sizeof pkg[0]) != 0
            || name[0] == '\0' || version[0] == '\0'
            || (group == GAUDIT_SOURCELESS_ABOVE_SOURCE) != (offered[0] != '\0'))
            return GAUDIT_BACKEND_ERROR;
        seen++;
        if (fn != NULL)
            fn(name, arch, version, (gaudit_sourceless_group)group,
               group == GAUDIT_SOURCELESS_ABOVE_SOURCE ? offered : NULL, ctx);
    }
    return ended ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
