/* SPDX-License-Identifier: GPL-3.0-only */
/* "gaudit-orchestrator report <plugin-id>": a plugin's report on collected
 * data. Reads the engine's input from stdin (built by the GUI from its
 * cache), runs gaudit-engine on it and passes the report on. The engine
 * starts with execve, a fixed path and argv and an empty environment;
 * what it writes is untrusted, so it is size limited here and parsed
 * strictly by the GUI. */
#include "config.h"

#include "report.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_IN      (512 * 1024)
#define MAX_OUT     (60 * 1024)   /* below the GUI's 64 KiB */
#define TIMEOUT_MS  10000         /* the engine's own limit is 2 s */

static int plain_id(const char *id)
{
    size_t n = strlen(id);
    if (n == 0 || n > 64 || id[0] == '.' || strstr(id, "..") != NULL)
        return 0;
    for (const char *p = id; *p != '\0'; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-'))
            return 0;
    return 1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

int gaudit_orchestrator_report(const char *plugin_id)
{
    if (plugin_id == NULL || !plain_id(plugin_id))
        return 2;
    /* The input, whole, before the engine starts. */
    char *in = malloc(MAX_IN + 1);
    size_t in_len = 0;
    while (in != NULL) {
        ssize_t n = read(STDIN_FILENO, in + in_len, MAX_IN + 1 - in_len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        in_len += (size_t)n;
        if (in_len > MAX_IN) {
            free(in);
            return 1;
        }
    }
    if (in == NULL)
        return 1;

    signal(SIGPIPE, SIG_IGN);
    int to[2], from[2];
    if (pipe2(to, O_CLOEXEC) != 0 || pipe2(from, O_CLOEXEC) != 0) {
        free(in);
        return 1;
    }
    pid_t self = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        free(in);
        return 1;
    }
    if (pid == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != self)
            _exit(125);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null < 0 || dup2(to[0], STDIN_FILENO) < 0 || dup2(from[1], STDOUT_FILENO) < 0
            || dup2(null, STDERR_FILENO) < 0)
            _exit(125);
        char *const argv[] = { (char *)GAUDIT_ENGINE_PATH, (char *)"report", (char *)plugin_id, NULL };
        char *const envp[] = { NULL };
        execve(GAUDIT_ENGINE_PATH, argv, envp);
        _exit(127);
    }
    close(to[0]);
    close(from[1]);
    /* The engine reads all of its input before it answers. */
    int ok = write_all(to[1], in, in_len) == 0;
    close(to[1]);
    free(in);

    char *out = malloc(MAX_OUT);
    size_t out_len = 0;
    long deadline = now_ms() + TIMEOUT_MS;
    while (ok && out != NULL) {
        long left = deadline - now_ms();
        if (left <= 0) {
            ok = 0;
            break;
        }
        struct pollfd p = { .fd = from[0], .events = POLLIN };
        int pr = poll(&p, 1, (int)left);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0) {
            ok = 0;
            break;
        }
        ssize_t n = read(from[0], out + out_len, MAX_OUT - out_len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            break;
        if (n < 0 || (out_len += (size_t)n) >= MAX_OUT)
            ok = 0;
    }
    close(from[0]);
    if (!ok)
        kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    ok = ok && out != NULL && WIFEXITED(status) && WEXITSTATUS(status) == 0
         && out_len > 0 && out[out_len - 1] == '\n';
    if (ok)
        ok = write_all(STDOUT_FILENO, out, out_len) == 0;
    free(out);
    return ok ? 0 : 1;
}
