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
 *   gaudit-orchestrator session
 *
 * Runs on request, one at a time, as the GUI asks for them on stdin ("run
 * firewall", "quit"). The first run starts the privileged helper through
 * pkexec (which asks for the administrator password) in its session mode;
 * later runs within the helper's lease use the same helper without asking
 * again. The helper decides when the lease ends, not this process. Writes
 * the events of gaudit/run.h: (elevated ...) when the helper starts and
 * ends, and per run the result and (end ...). When the GUI goes away, the
 * helper's input is closed and it ends its session.
 *
 * The GUI treats this output as untrusted input: it is size limited and
 * parsed strictly, line by line. The helper's output is untrusted here in
 * the same way. The rule engine comes later. */
#include "config.h"

#include "gaudit/backend.h"
#include "gaudit/probe.h"
#include "gaudit/run.h"
#include "gaudit/sourceless.h"

#include "collector.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

/* --- Session: runs on request through the helper ------------------------ */

#define PKEXEC_PATH      "/usr/bin/pkexec"
#define RUN_DEADLINE_MS  (5 * 60 * 1000)  /* includes typing the password */
#define MAX_HELPER_OUT   (256 * 1024)     /* over a whole session */
#define MAX_LINE_LEN     1024

static int emit(const gaudit_run_event *ev)
{
    char line[512];
    if (gaudit_run_format(ev, line, sizeof line) != 0)
        return -1;
    size_t len = strlen(line), done = 0;
    while (done < len) {
        ssize_t n = write(STDOUT_FILENO, line + done, len - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static int emit_end(gaudit_run_status status)
{
    gaudit_run_event ev = { .type = GAUDIT_RUN_EVENT_END, .status = status };
    return emit(&ev);
}

static int emit_elevated(int on)
{
    gaudit_run_event ev = { .type = GAUDIT_RUN_EVENT_ELEVATED, .elevated = on };
    return emit(&ev);
}

/* Reading lines from a descriptor. */
typedef struct {
    int fd;
    char buf[MAX_LINE_LEN];
    size_t used;
} line_reader;

/* After data is available: reads it and calls fn for each complete line.
 * 1 while open, 0 at end of input, -1 on an over-long line or error. */
static int read_lines(line_reader *r, int (*fn)(char *line, void *ctx), void *ctx)
{
    ssize_t n;
    do
        n = read(r->fd, r->buf + r->used, sizeof r->buf - r->used);
    while (n < 0 && errno == EINTR);
    if (n < 0)
        return -1;
    if (n == 0)
        return r->used == 0 ? 0 : -1;  /* ending mid-line breaks the protocol */
    r->used += (size_t)n;
    char *nl;
    while ((nl = memchr(r->buf, '\n', r->used)) != NULL) {
        *nl = '\0';
        size_t len = (size_t)(nl - r->buf);
        if (memchr(r->buf, '\0', len) != NULL || fn(r->buf, ctx) != 0)
            return -1;
        r->used -= len + 1;
        memmove(r->buf, nl + 1, r->used);
    }
    return r->used < sizeof r->buf ? 1 : -1;
}

typedef struct {
    /* The helper (through pkexec), while it lives. */
    pid_t pid;
    int to_helper;          /* its stdin; closing it ends the session */
    line_reader from_helper;
    int started;            /* (helper-start ...) seen: running as root */
    size_t helper_bytes;

    /* The run under way, if any. */
    int running;
    int overdue;            /* its deadline has passed and been dealt with */
    int queued;             /* waits for the ending helper to be gone */
    struct timespec run_start;
    int have_result;
    gaudit_firewall_report fw;
} session_state;

static void close_helper_input(session_state *st)
{
    if (st->to_helper >= 0) {
        close(st->to_helper);
        st->to_helper = -1;
    }
}

static int start_helper(session_state *st)
{
    int in[2], out[2];
    if (pipe2(in, O_CLOEXEC) != 0)
        return -1;
    if (pipe2(out, O_CLOEXEC) != 0) {
        close(in[0]);
        close(in[1]);
        return -1;
    }
    pid_t self = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        close(in[0]); close(in[1]); close(out[0]); close(out[1]);
        return -1;
    }
    if (pid == 0) {
        /* pkexec with a fixed argv and an empty environment; it finds the
         * session's authentication agent on its own. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != self)
            _exit(125);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null < 0 || dup2(in[0], STDIN_FILENO) < 0 || dup2(out[1], STDOUT_FILENO) < 0
            || dup2(null, STDERR_FILENO) < 0)
            _exit(125);
        char *const argv[] = { (char *)PKEXEC_PATH, (char *)"--disable-internal-agent",
                               (char *)GAUDIT_HELPER_PATH, (char *)"session", NULL };
        char *const envp[] = { NULL };
        execve(PKEXEC_PATH, argv, envp);
        _exit(125);
    }
    close(in[0]);
    close(out[1]);
    st->pid = pid;
    st->to_helper = in[1];
    st->from_helper.fd = out[0];
    st->from_helper.used = 0;
    st->started = 0;
    st->helper_bytes = 0;
    return 0;
}

static int on_helper_line(char *line, void *ctx)
{
    session_state *st = ctx;
    st->helper_bytes += strlen(line) + 1;
    if (st->helper_bytes > MAX_HELPER_OUT)
        return -1;
    long long version, caller, idle, cap, ok, failed;
    long long tables, chains, ichains, idrop, irules, rules, legacy;
    char reason[16];
    const gaudit_sexpr_field start[] = {
        { .key = "version", .value = &version, .min = 1, .max = 1 },
        { .key = "caller",  .value = &caller,  .min = -1, .max = 4294967295LL },
        { .key = "idle",    .value = &idle,    .max = 86400 },
        { .key = "cap",     .value = &cap,     .max = 86400 },
    };
    const gaudit_sexpr_field summary[] = {
        { .key = "version",       .value = &version, .min = 1, .max = 1 },
        { .key = "caller",        .value = &caller,  .min = -1, .max = 4294967295LL },
        { .key = "checks-ok",     .value = &ok,      .max = 100 },
        { .key = "checks-failed", .value = &failed,  .max = 100 },
    };
    const gaudit_sexpr_field fw[] = {
        { .key = "tables",       .value = &tables,  .max = 100000000 },
        { .key = "chains",       .value = &chains,  .max = 100000000 },
        { .key = "input-chains", .value = &ichains, .max = 100000000 },
        { .key = "input-drop",   .value = &idrop,   .max = 100000000 },
        { .key = "input-rules",  .value = &irules,  .max = 100000000 },
        { .key = "rules",        .value = &rules,   .max = 100000000 },
        { .key = "legacy",       .value = &legacy,  .max = 1000 },
    };
    const gaudit_sexpr_field end[] = {
        { .key = "reason", .text = reason, .text_len = sizeof reason },
    };

    if (!st->started) {
        if (gaudit_sexpr_parse(line, "helper-start", start, 4) != 0 || idle == 0 || cap == 0)
            return -1;
        st->started = 1;
        return emit_elevated(1);
    }
    if (gaudit_sexpr_parse(line, "helper-end", end, 1) == 0) {
        close_helper_input(st);  /* leaving: nothing more goes to it */
        return 0;
    }
    if (!st->running)
        return -1;  /* nothing else comes unasked */
    if (!st->have_result && gaudit_sexpr_parse(line, "firewall", fw, sizeof fw / sizeof fw[0]) == 0) {
        st->have_result = 1;
        st->fw = (gaudit_firewall_report){
            .tables = (unsigned)tables, .input_chains = (unsigned)ichains,
            .input_drop = (unsigned)idrop, .input_rules = (unsigned)irules,
            .rules = (unsigned)rules, .legacy = (unsigned)legacy,
        };
        st->fw.verdict = gaudit_firewall_verdict(&st->fw);
        /* Read here, as the user: what the firewall stands in front of. */
        unsigned services = 0, own = 0;
        const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
        if (pkg->listening != NULL && pkg->listening(&services, &own) == GAUDIT_BACKEND_OK)
            st->fw.listening = services;
        return 0;
    }
    if (gaudit_sexpr_parse(line, "helper", summary, 4) == 0) {
        /* The end of this run. */
        st->running = 0;
        if (failed == 0 && st->have_result) {
            gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_FIREWALL, .firewall = st->fw };
            if (emit(&res) != 0)
                return -1;
            return emit_end(GAUDIT_RUN_OK);
        }
        return emit_end(GAUDIT_RUN_FAILED);
    }
    return -1;
}

static int send_helper(session_state *st, const char *cmd);

/* The helper's output has ended (or broke the protocol): reap it and say
 * how the run under way, if any, ended. */
static int helper_gone(session_state *st, int broken)
{
    close_helper_input(st);
    close(st->from_helper.fd);
    st->from_helper.fd = -1;
    if (broken && !st->started)
        kill(st->pid, SIGKILL);  /* still pkexec: ours to stop */
    int status = 0;
    while (waitpid(st->pid, &status, 0) < 0 && errno == EINTR)
        ;
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    st->pid = -1;
    int r = 0;
    int was_started = st->started;
    if (was_started && emit_elevated(0) != 0)
        r = -1;
    st->started = 0;
    if (st->queued) {
        /* A run asked for while the lease ran out: a new helper, which
         * asks for the password again. */
        st->queued = 0;
        if (start_helper(st) != 0 || send_helper(st, "firewall\n") != 0) {
            st->running = 0;
            return emit_end(GAUDIT_RUN_FAILED) != 0 ? -1 : r;
        }
        return r;
    }
    if (st->running) {
        st->running = 0;
        /* pkexec: 126 the dialog was dismissed, 127 not authorized. */
        gaudit_run_status s = GAUDIT_RUN_FAILED;
        if (!was_started && !broken)
            s = code == 126 ? GAUDIT_RUN_CANCELLED : code == 127 ? GAUDIT_RUN_DENIED : GAUDIT_RUN_FAILED;
        if (emit_end(s) != 0)
            r = -1;
    }
    return r;
}

static int send_helper(session_state *st, const char *cmd)
{
    size_t len = strlen(cmd);
    ssize_t n;
    do
        n = write(st->to_helper, cmd, len);
    while (n < 0 && errno == EINTR);
    return n == (ssize_t)len ? 0 : -1;
}

/* A command from the GUI: "run firewall" or "quit". */
static int on_gui_line(char *line, void *ctx)
{
    session_state *st = ctx;
    if (strcmp(line, "quit") == 0) {
        close_helper_input(st);  /* the helper ends its session */
        return 0;
    }
    if (strcmp(line, "run firewall") != 0 || st->running)
        return -1;  /* unknown, or one run at a time */
    st->running = 1;
    st->overdue = 0;
    st->have_result = 0;
    clock_gettime(CLOCK_MONOTONIC, &st->run_start);
    if (st->pid > 0 && st->to_helper < 0) {
        st->queued = 1;  /* the helper is ending; a new one follows */
        return 0;
    }
    if (st->pid <= 0 && start_helper(st) != 0) {
        st->running = 0;
        return emit_end(GAUDIT_RUN_FAILED);
    }
    /* Waits in the pipe until the helper runs (after the password). */
    if (send_helper(st, "firewall\n") != 0)
        close_helper_input(st);  /* the helper's end reports the run */
    return 0;
}

static int run_session(void)
{
    signal(SIGPIPE, SIG_IGN);  /* a vanished helper shows up as EPIPE */
    session_state st = { .pid = -1, .to_helper = -1, .from_helper = { .fd = -1 } };
    line_reader gui = { .fd = STDIN_FILENO };
    int gui_open = 1, failed = 0;

    while (gui_open || st.pid > 0) {
        struct pollfd pfd[2] = {
            { .fd = gui_open ? STDIN_FILENO : -1, .events = POLLIN },
            { .fd = st.from_helper.fd, .events = POLLIN },
        };
        int timeout = -1;
        if (st.running && !st.overdue) {
            long left = RUN_DEADLINE_MS - elapsed_ms(&st.run_start);
            timeout = left > 0 ? (int)left : 0;
        }
        int pr = poll(pfd, 2, timeout);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr < 0)
            return 1;
        if (pr == 0) {
            /* The run took too long. Still waiting for the password:
             * pkexec is ours to stop, and its end reports the run. Already
             * root: the helper can only be asked to stop, by closing its
             * input; the run is reported failed now, and anything it still
             * says about it breaks the protocol. */
            st.overdue = 1;
            close_helper_input(&st);
            if (!st.started && st.pid > 0) {
                kill(st.pid, SIGKILL);
            } else if (st.started) {
                st.running = 0;
                if (emit_end(GAUDIT_RUN_FAILED) != 0)
                    return 1;
            }
            continue;
        }
        if (pfd[0].revents != 0) {
            int r = read_lines(&gui, on_gui_line, &st);
            if (r < 0) {
                failed = 1;  /* the GUI broke the protocol: end everything */
                gui_open = 0;
                close_helper_input(&st);
            } else if (r == 0) {
                gui_open = 0;  /* the GUI is gone: so is the session */
                close_helper_input(&st);
            }
        }
        if (st.pid > 0 && pfd[1].revents != 0) {
            int r = read_lines(&st.from_helper, on_helper_line, &st);
            if (r <= 0 && helper_gone(&st, r < 0) != 0)
                return 1;
        }
    }
    return failed;
}

/* --- packages: the list of packages without a source -------------------- */

typedef struct {
    unsigned count, shown;
    int failed;
} list_state;

static void on_sourceless(const char *name, const char *arch, const char *version,
                          gaudit_sourceless_group group, const char *offered, void *ctx)
{
    list_state *st = ctx;
    st->count++;
    if (st->failed || st->shown >= GAUDIT_SOURCELESS_MAX_SHOWN)
        return;
    gaudit_sourceless_package p = { .group = group };
    /* Names longer than the fields are counted but not sent. */
    if (snprintf(p.name, sizeof p.name, "%s", name) >= (int)sizeof p.name
        || snprintf(p.arch, sizeof p.arch, "%s", arch != NULL ? arch : "") >= (int)sizeof p.arch
        || snprintf(p.version, sizeof p.version, "%s", version) >= (int)sizeof p.version
        || snprintf(p.offered, sizeof p.offered, "%s", offered != NULL ? offered : "")
               >= (int)sizeof p.offered)
        return;
    char line[1024];
    if (gaudit_sourceless_format_package(&p, line, sizeof line) != 0
        || fputs(line, stdout) == EOF) {
        st->failed = 1;
        return;
    }
    st->shown++;
}

static int list_packages(void)
{
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    list_state st = { 0 };
    gaudit_sourceless_summary sum = { .status = GAUDIT_SOURCELESS_UNSUPPORTED };
    if (pkg->sourceless_packages != NULL) {
        gaudit_backend_status r = pkg->sourceless_packages(on_sourceless, &st);
        sum.status = r == GAUDIT_BACKEND_OK && !st.failed ? GAUDIT_SOURCELESS_OK
                   : r == GAUDIT_BACKEND_NOT_IMPLEMENTED ? GAUDIT_SOURCELESS_UNSUPPORTED
                   : GAUDIT_SOURCELESS_UNKNOWN;
    }
    if (sum.status == GAUDIT_SOURCELESS_OK) {
        sum.count = st.count;
        sum.shown = st.shown;
    } else if (st.shown > 0) {
        return 1;  /* lines already sent for a list that is not valid: none of it counts */
    }
    char line[256];
    if (gaudit_sourceless_format_summary(&sum, line, sizeof line) != 0 || fputs(line, stdout) == EOF)
        return 1;
    return fflush(stdout) == 0 ? 0 : 1;
}

/* --- Home status ------------------------------------------------------------ */

static int status_refresh(void)
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

int main(int argc, char *argv[])
{
    if (argc == 1)
        return status_refresh();
    if (argc == 2 && strcmp(argv[1], "session") == 0)
        return run_session();
    if (argc == 2 && strcmp(argv[1], "packages") == 0)
        return list_packages();
#if GAUDIT_DEVELOPER_BUILD
    /* Developer builds only: see the pages for missing software. */
    static const char pretend[] = "--pretend-missing=";
    if (argc == 2 && strncmp(argv[1], pretend, sizeof pretend - 1) == 0) {
        if (gaudit_capability_pretend_missing(argv[1] + sizeof pretend - 1) != 0)
            return 2;
        return status_refresh();
    }
#endif
    fputs("usage: gaudit-orchestrator [session | packages]\n", stderr);
    return 2;
}
