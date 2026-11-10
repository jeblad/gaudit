/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-helper: privileged helper, started via pkexec.
 *
 *   gaudit-helper selftest | firewall | session
 *
 * Writes (helper-start ...) as soon as it runs as root, so the caller
 * knows the authorization went through. Then runs each check in its own
 * child process, reduced to what that check needs (sandbox.c), writes one
 * S-expression line per check on stdout, and ends with a (helper ...)
 * summary line.
 *
 *   selftest  the privileges the checks actually end up with, so the
 *             sandbox can be verified
 *   firewall  the nftables ruleset (root with CAP_NET_ADMIN only) and
 *             whether legacy iptables tables are loaded
 *   session   keeps the rights for more commands (one per line on stdin:
 *             a command name, or "quit") within the lease of lease.h, and
 *             ends with (helper-end (reason ...)): idle, cap, quit, eof or
 *             bad-command. An unknown command ends the session.
 *
 * Never translates output: it runs as root, and its output is a
 * language-neutral protocol. Verifying the signed manifest, inspecting the
 * other gaudit processes and the root-owned log come later. */
#include "config.h"

#include "lease.h"
#include "nft.h"
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

/* --- firewall ------------------------------------------------------------- */

/* Tables loaded in legacy iptables (x_tables), which nftables does not
 * show: a system using them would otherwise look unprotected. Lines in
 * /proc/net/ip{,6}_tables_names, which are absent when the legacy modules
 * are not loaded. */
static int legacy_tables(void)
{
    static const char *const files[] = { "/proc/net/ip_tables_names", "/proc/net/ip6_tables_names" };
    int n = 0;
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        FILE *f = fopen(files[i], "re");
        if (f == NULL)
            continue;
        char line[64];
        while (fgets(line, sizeof line, f) != NULL)
            if (line[0] != '\n')
                n++;
        fclose(f);
    }
    return n;
}

static void firewall(void *ctx)
{
    (void)ctx;
    gaudit_nft_summary s;
    if (gaudit_nft_read(&s) != 0)
        _exit(1);  /* no line: the caller reports the check as failed */
    printf("(firewall (tables %u) (chains %u) (input-chains %u) (input-drop %u)"
           " (input-rules %u) (rules %u) (legacy %d))\n",
           s.tables, s.chains, s.input_chains, s.input_drop, s.input_rules, s.rules,
           legacy_tables());
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

/* --- Commands ------------------------------------------------------------- */

typedef struct {
    const char *variant;
    gaudit_sandbox spec;
    check_fn fn;
} check_def;

static const cap_value_t read_caps[] = { CAP_DAC_READ_SEARCH };
static const cap_value_t net_caps[] = { CAP_NET_ADMIN };

static const check_def selftest_checks[] = {
    { "nobody",          { .to_nobody = 1 },                                  selftest },
    { "dac-read-search", { .to_nobody = 0, .caps = read_caps, .n_caps = 1 }, selftest },
};
static const check_def firewall_checks[] = {
    { "firewall",        { .to_nobody = 0, .caps = net_caps, .n_caps = 1 },  firewall },
};

static const struct {
    const char *name;
    const check_def *checks;
    size_t n_checks;
} commands[] = {
    { "selftest", selftest_checks, sizeof selftest_checks / sizeof selftest_checks[0] },
    { "firewall", firewall_checks, sizeof firewall_checks / sizeof firewall_checks[0] },
};

static int find_command(const char *name)
{
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
        if (strcmp(commands[i].name, name) == 0)
            return (int)i;
    return -1;
}

/* Runs every check of command i and ends with the (helper ...) summary.
 * 0 when all checks succeeded. */
static int run_command(int i, long caller)
{
    int ok = 0, failed = 0;
    for (size_t c = 0; c < commands[i].n_checks; c++) {
        const check_def *def = &commands[i].checks[c];
        char out[MAX_CHECK_OUTPUT];
        if (run_check(&def->spec, def->fn, (void *)def->variant, out, sizeof out) == 0) {
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

/* --- Session ------------------------------------------------------------- */

#define MAX_COMMAND 64

/* One command line from stdin within timeout_ms, without the newline.
 * 1: a line; 0: timeout; -1: end of input, error, or a line too long. */
static int read_command(char *line, size_t len, long long timeout_ms)
{
    static char buf[MAX_COMMAND];
    static size_t used;
    long long deadline = gaudit_lease_now() + timeout_ms;
    for (;;) {
        char *nl = memchr(buf, '\n', used);
        if (nl != NULL) {
            size_t n = (size_t)(nl - buf);
            if (n >= len)
                return -1;
            memcpy(line, buf, n);
            line[n] = '\0';
            used -= n + 1;
            memmove(buf, nl + 1, used);
            return 1;
        }
        if (used >= sizeof buf)
            return -1;
        long long left = deadline - gaudit_lease_now();
        if (left <= 0)
            return 0;
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        int pr = poll(&pfd, 1, left > 60000 ? 60000 : (int)left);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr < 0)
            return -1;
        if (pr == 0)
            continue;  /* re-check the deadline on the boot clock */
        ssize_t n = read(STDIN_FILENO, buf + used, sizeof buf - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        used += (size_t)n;
    }
}

static int session(long caller)
{
    gaudit_lease lease;
    gaudit_lease_begin(&lease, gaudit_lease_now());
    const char *reason = "eof";
    int status = 0;
    for (;;) {
        long long wait_ms;
        gaudit_lease_state st = gaudit_lease_check(&lease, gaudit_lease_now(), &wait_ms);
        if (st != GAUDIT_LEASE_LIVE) {
            reason = st == GAUDIT_LEASE_CAP ? "cap" : "idle";
            break;
        }
        char line[MAX_COMMAND];
        int r = read_command(line, sizeof line, wait_ms);
        if (r == 0)
            continue;  /* the lease decides on the next round */
        if (r < 0) {
            reason = "eof";
            break;
        }
        if (strcmp(line, "quit") == 0) {
            reason = "quit";
            break;
        }
        int i = find_command(line);
        if (i < 0) {
            reason = "bad-command";
            status = 1;
            break;
        }
        /* A run under way when the cap is reached may finish. */
        run_command(i, caller);
        gaudit_lease_renew(&lease, gaudit_lease_now());
    }
    printf("(helper-end (reason \"%s\"))\n", reason);
    return fflush(stdout) == 0 ? status : 1;
}

/* --- main ----------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    int cmd = argc == 2 ? find_command(argv[1]) : -1;
    int is_session = argc == 2 && strcmp(argv[1], "session") == 0;
    if (cmd < 0 && !is_session) {
        fputs("usage: gaudit-helper selftest | firewall | session\n", stderr);
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
    /* Nothing inherited beyond stdin (commands in a session), stdout (to
     * the caller) and stderr. */
    if (syscall(SYS_close_range, 3U, ~0U, 0) != 0)
        return 1;

    /* The lease in seconds, so the caller can show it; 0 0 for a single
     * command. */
    printf("(helper-start (version 1) (caller %ld) (idle %lld) (cap %lld))\n", caller,
           is_session ? GAUDIT_LEASE_IDLE_MS / 1000 : 0, is_session ? GAUDIT_LEASE_CAP_MS / 1000 : 0);
    if (fflush(stdout) != 0)
        return 1;
    return is_session ? session(caller) : run_command(cmd, caller);
}
