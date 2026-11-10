/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-orchestrator: runs as the user, started by the GUI for each status
 * refresh. It runs the Home status probes (which start their own
 * collectors) and writes one line per result on stdout as soon as it is
 * known, so the GUI can fill in each row on its own.
 *
 * Each probe task runs in its own child process, side by side: a slow task
 * does not hold up the others, and the probe code needs no thread safety.
 * A child writes all its lines with one write() of at most PIPE_BUF bytes,
 * which the kernel keeps whole, so lines from different children never
 * mix. A child still running at the deadline is killed and its rows stay
 * unknown in the GUI.
 *
 * The GUI treats this output as untrusted input: it is size limited and
 * parsed strictly, line by line (gaudit_probe_parse_line). Starting the
 * privileged helper and the rule engine comes later. */
#include "config.h"

#include "gaudit/backend.h"
#include "gaudit/probe.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Below the GUI's own timeout (60 s), so the GUI sees an orderly end. */
#define DEADLINE_MS 50000
#define POLL_MS     20

static int run_task(int task, const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                    int64_t now)
{
    gaudit_probe_result results[GAUDIT_PROBE_COUNT];
    gaudit_probe_init(results);
    gaudit_probe_run_task(task, pkg, expected, now, results);

    char buf[PIPE_BUF];
    size_t used = 0;
    unsigned kinds = gaudit_probe_task_kinds(task);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        if (!(kinds & (1u << k)))
            continue;
        if (gaudit_probe_format(&results[k], buf + used, sizeof buf - used) != 0)
            return 1;
        used += strlen(buf + used);
    }
    ssize_t n;
    do
        n = write(STDOUT_FILENO, buf, used);
    while (n < 0 && errno == EINTR);
    return n == (ssize_t)used ? 0 : 1;
}

static long elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

int main(void)
{
    /* Decided once, before the children start, so they all agree. */
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    const gaudit_pkg_backend *expected = gaudit_pkg_backend_expected();
    int64_t now = (int64_t)time(NULL);

    pid_t self = getpid();
    pid_t pids[GAUDIT_PROBE_TASK_COUNT];
    int running = 0, failed = 0;
    for (int t = 0; t < GAUDIT_PROBE_TASK_COUNT; t++) {
        pids[t] = fork();
        if (pids[t] == 0) {
            /* Die with the orchestrator, so a killed refresh leaves no
             * task holding the GUI's pipe open. */
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != self)
                _exit(1);
            _exit(run_task(t, pkg, expected, now));
        }
        if (pids[t] < 0)
            failed = 1;
        else
            running++;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (running > 0) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid < 0 && errno == EINTR)
            continue;
        if (pid < 0)
            break;
        if (pid > 0) {
            running--;
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
                failed = 1;
            for (int t = 0; t < GAUDIT_PROBE_TASK_COUNT; t++)
                if (pids[t] == pid)
                    pids[t] = -1;
            continue;
        }
        if (elapsed_ms(&start) >= DEADLINE_MS) {
            for (int t = 0; t < GAUDIT_PROBE_TASK_COUNT; t++)
                if (pids[t] > 0)
                    kill(pids[t], SIGKILL);
            failed = 1;
            while (running > 0 && (waitpid(-1, NULL, 0) > 0 || errno == EINTR))
                running--;
            break;
        }
        struct timespec pause = { 0, POLL_MS * 1000000L };
        nanosleep(&pause, NULL);
    }
    return failed ? 1 : 0;
}
