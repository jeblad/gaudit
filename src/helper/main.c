/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-helper: privileged helper, started via pkexec.
 *
 *   gaudit-helper selftest
 *
 * Runs each check in its own child process, reduced to what that check
 * needs (sandbox.c), and writes one S-expression line per check on stdout,
 * followed by a (helper ...) summary line. The only command so far is
 * "selftest", whose checks report the privileges they actually ended up
 * with, so the sandbox can be verified.
 *
 * Never translates output: it runs as root, and its output is a
 * language-neutral protocol. Verifying the signed manifest, inspecting the
 * other gaudit processes and the root-owned log come later. */
#include "config.h"

#include "sandbox.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CHECK_TIMEOUT_MS 10000
#define MAX_CHECK_OUTPUT 4096

/* --- Running one check ---------------------------------------------------- */

typedef void (*check_fn)(void *ctx);

static long elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

/* Fork, sandbox the child as spec says, run fn there with stdout on a pipe,
 * and collect at most MAX_CHECK_OUTPUT bytes within the timeout.
 * 0 on success (buf holds the output), -1 otherwise. */
static int run_check(const gaudit_sandbox *spec, check_fn fn, void *ctx, char *buf, size_t len)
{
    int fds[2];
    if (len < 2 || pipe2(fds, O_CLOEXEC) != 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: nothing of the check runs before the sandbox is in place. */
        if (dup2(fds[1], STDOUT_FILENO) < 0
            || gaudit_sandbox_close_fds(-1) != 0
            || gaudit_sandbox_enter(spec) != 0)
            _exit(2);
        fn(ctx);
        _exit(fflush(stdout) == 0 ? 0 : 1);
    }

    close(fds[1]);
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t used = 0;
    int failed = 0;
    for (;;) {
        long left = CHECK_TIMEOUT_MS - elapsed_ms(&start);
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        int pr = left > 0 ? poll(&pfd, 1, (int)left) : 0;
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0) {
            failed = 1;  /* timeout */
            break;
        }
        ssize_t n = read(fds[0], buf + used, len - 1 - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            failed = 1;
            break;
        }
        if (n == 0)
            break;
        used += (size_t)n;
        if (used >= len - 1) {
            failed = 1;  /* more than any check may write */
            break;
        }
    }
    close(fds[0]);
    buf[used] = '\0';
    if (failed)
        kill(pid, SIGKILL);

    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return !failed && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* --- selftest ------------------------------------------------------------- */

static int seccomp_mode(void)
{
    FILE *f = fopen("/proc/self/status", "re");
    if (f == NULL)
        return -1;
    char line[256];
    int mode = -1;
    while (fgets(line, sizeof line, f) != NULL)
        if (sscanf(line, "Seccomp: %d", &mode) == 1)
            break;
    fclose(f);
    return mode;
}

static int open_fds(void)
{
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL)
        return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL)
        if (de->d_name[0] != '.')
            n++;
    closedir(dir);
    return n - 1;  /* the directory stream itself */
}

static void selftest(void *ctx)
{
    const char *variant = ctx;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);

    cap_t caps = cap_get_proc();
    char *caps_text = caps != NULL ? cap_to_text(caps, NULL) : NULL;

    int env = 0;
    for (char **e = environ; e != NULL && *e != NULL; e++)
        env++;

    errno = 0;
    int ptrace_blocked = ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 && errno == EPERM;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int network_blocked = sock < 0 && errno == EPERM;
    if (sock >= 0)
        close(sock);

    printf("(selftest (variant \"%s\") (ruid %u) (euid %u) (suid %u) (rgid %u) (egid %u)"
           " (caps \"%s\") (no-new-privs %d) (seccomp %d) (fds %d) (env %d)"
           " (ptrace-blocked %d) (network-blocked %d))\n",
           variant, (unsigned)ruid, (unsigned)euid, (unsigned)suid, (unsigned)rgid, (unsigned)egid,
           caps_text != NULL ? caps_text : "?", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
           seccomp_mode(), open_fds(), env, ptrace_blocked, network_blocked);
    cap_free(caps_text);
    cap_free(caps);
}

/* --- main ----------------------------------------------------------------- */

/* PKEXEC_UID as set by pkexec, -1 if absent or not a plain number. Only
 * reported; never used to decide anything. */
static long caller_uid(void)
{
    const char *s = getenv("PKEXEC_UID");
    if (s == NULL || *s == '\0' || strlen(s) > 10)
        return -1;
    long v = 0;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        v = v * 10 + (*p - '0');
    }
    return v;
}

int main(int argc, char *argv[])
{
    if (argc != 2 || strcmp(argv[1], "selftest") != 0) {
        fputs("usage: gaudit-helper selftest\n", stderr);
        return 2;
    }
    if (getuid() != 0 || geteuid() != 0) {
        fputs("gaudit-helper: must run as root (through pkexec)\n", stderr);
        return 1;
    }

    long caller = caller_uid();
    if (clearenv() != 0)
        return 1;
    umask(077);
    if (chdir("/") != 0)
        return 1;
    /* Nothing inherited beyond stdin, stdout (to the caller) and stderr. */
    if (syscall(SYS_close_range, 3U, ~0U, 0) != 0)
        return 1;

    static const cap_value_t read_caps[] = { CAP_DAC_READ_SEARCH };
    static const struct {
        const char *variant;
        gaudit_sandbox spec;
    } runs[] = {
        { "nobody",          { .to_nobody = 1 } },
        { "dac-read-search", { .to_nobody = 0, .caps = read_caps, .n_caps = 1 } },
    };

    int ok = 0, failed = 0;
    for (size_t i = 0; i < sizeof runs / sizeof runs[0]; i++) {
        char out[MAX_CHECK_OUTPUT];
        if (run_check(&runs[i].spec, selftest, (void *)runs[i].variant, out, sizeof out) == 0) {
            fputs(out, stdout);
            ok++;
        } else {
            failed++;
        }
    }
    printf("(helper (version 1) (caller %ld) (checks-ok %d) (checks-failed %d))\n",
           caller, ok, failed);
    return fflush(stdout) == 0 && failed == 0 ? 0 : 1;
}
