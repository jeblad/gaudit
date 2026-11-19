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
 * firewall", "run integrity", "elevate", "quit"). "elevate" only starts the
 * helper, so the user can switch to administrator before any check; it
 * ends ok once the helper runs as root. The first run starts the privileged helper through
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
#include "report.h"
#include "fix-mode.h"
#include "secrets-mode.h"
#include "shared-mode.h"
#include "cloud-mode.h"
#include "updates-mode.h"
#include "apt-ops.h"
#include "sandbox.h"
#include "vendor.h"

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
/* What the GUI may ask for, the helper command it becomes (NULL: none,
 * only the helper itself), and how long the run may take, typing the
 * password included. */
static const struct {
    const char *request;
    const char *helper_cmd;
    long deadline_ms;
} runs[] = {
    { "run firewall",  "firewall\n",  5 * 60 * 1000L },
    { "run integrity", "integrity\n", 20 * 60 * 1000L },  /* the helper allows 15 */
    { "elevate",       NULL,          5 * 60 * 1000L },
    /* Writing gAudit's own configuration (conf-write.h), on request. */
    { "run automatic-updates-on",     "automatic-updates-on\n",     5 * 60 * 1000L },
    { "run automatic-updates-remove", "automatic-updates-remove\n", 5 * 60 * 1000L },
    /* A system tool on request (common/apt-ops.h); an upgrade can take long.
     * "run reinstall <package> ..." carries its packages (RUN_EXEC). */
    { "run apt-update",         "apt-update\n",         50 * 60 * 1000L },
    { "run apt-upgrade",        "apt-upgrade\n",        50 * 60 * 1000L },
    { "run apt-upgrade-update", "apt-upgrade-update\n", 50 * 60 * 1000L },
    { "run enable-apt-timers",  "enable-apt-timers\n",  50 * 60 * 1000L },
    { "run reinstall",          NULL,                  50 * 60 * 1000L },
    /* "run add-ppa <ppa>" sets up again a PPA the release upgrade switched off. */
    { "run add-ppa",            NULL,                  50 * 60 * 1000L },
    /* A known vendor package (common/vendor.h): "run vendor-verify <id>
     * <version> <path>" checks the user's download in the helper's own
     * folder; "run vendor-install <id> [anyway]" installs that copy. */
    { "run vendor-verify",      NULL,                  15 * 60 * 1000L },
    { "run vendor-install",     NULL,                  50 * 60 * 1000L },
    /* gAudit checking itself (selfcheck.h): its files and these processes. */
    { "run self-check",         "self-check\n",        5 * 60 * 1000L },
};
enum { RUN_FIREWALL, RUN_INTEGRITY, RUN_ELEVATE, RUN_CONF_ON, RUN_CONF_REMOVE,
       RUN_APT_UPDATE, RUN_APT_UPGRADE, RUN_APT_UPGRADE_UPDATE, RUN_APT_TIMERS, RUN_REINSTALL,
       RUN_ADD_PPA, RUN_VENDOR_VERIFY, RUN_VENDOR_INSTALL, RUN_SELF_CHECK, RUN_KINDS };

static int is_exec_kind(int kind)
{
    return kind >= RUN_APT_UPDATE && kind <= RUN_ADD_PPA;
}

/* The runs whose request carries arguments after its words. */
static int takes_args(int kind)
{
    return kind == RUN_REINSTALL || kind == RUN_ADD_PPA || kind == RUN_VENDOR_VERIFY
           || kind == RUN_VENDOR_INSTALL;
}

static int is_vendor_kind(int kind)
{
    return kind == RUN_VENDOR_VERIFY || kind == RUN_VENDOR_INSTALL;
}
#define MAX_HELPER_OUT   (256 * 1024)     /* over a whole session */
#define MAX_LINE_LEN     4096  /* "run reinstall" carries its packages */

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
    int kind;               /* RUN_FIREWALL, RUN_INTEGRITY, RUN_ELEVATE */
    int have_result;
    gaudit_firewall_report fw;
    gaudit_integrity_report integrity;
    gaudit_integrity_file files[GAUDIT_INTEGRITY_SHOWN];
    unsigned n_files;
    gaudit_conf_report conf;
    gaudit_exec_report exec;
    gaudit_vendor_report vendor;
    gaudit_self_report self;
    gaudit_self_file self_files[GAUDIT_SELF_SHOWN];
    gaudit_self_process self_processes[GAUDIT_SELF_SHOWN];
    unsigned n_self_files, n_self_processes;
    char helper_line[4096];     /* what goes to the helper for this run */
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

/* A line of an integrity run: findings, the result, then the helper's
 * summary. Collected, and passed on only when the run has succeeded. */
static int on_integrity_line(session_state *st, char *line, long long *failed,
                             const gaudit_sexpr_field *summary)
{
    static const char *const kinds[] = { "changed", "missing", "unreadable" };
    char kind[16];
    gaudit_integrity_file f = { 0 };
    const gaudit_sexpr_field file[] = {
        { .key = "kind",    .text = kind, .text_len = sizeof kind },
        { .key = "package", .text = f.package, .text_len = sizeof f.package },
        { .key = "path",    .text = f.path, .text_len = sizeof f.path },
    };
    if (!st->have_result && gaudit_sexpr_parse(line, "integrity-file", file, 3) == 0) {
        if (st->n_files >= GAUDIT_INTEGRITY_SHOWN || f.package[0] == '\0' || f.path[0] != '/')
            return -1;
        int k = -1;
        for (int i = 0; i < 3; i++)
            if (strcmp(kind, kinds[i]) == 0)
                k = i;
        if (k < 0)
            return -1;
        f.kind = (gaudit_integrity_file_kind)k;
        st->files[st->n_files++] = f;
        return 0;
    }
    long long v[12];
    static const char *const keys[12] = {
        "packages", "files", "checked", "changed", "missing", "unreadable", "excluded",
        "diverted", "bad-lines", "megabytes", "shown", "seconds",
    };
    gaudit_sexpr_field integ[12];
    for (int i = 0; i < 12; i++)
        integ[i] = (gaudit_sexpr_field){ .key = keys[i], .value = &v[i], .max = 100000000LL };
    if (!st->have_result && gaudit_sexpr_parse(line, "integrity", integ, 12) == 0) {
        gaudit_integrity_report *r = &st->integrity;
        *r = (gaudit_integrity_report){
            .packages = (unsigned long)v[0], .files = (unsigned long)v[1],
            .checked = (unsigned long)v[2], .changed = (unsigned long)v[3],
            .missing = (unsigned long)v[4], .unreadable = (unsigned long)v[5],
            .excluded = (unsigned long)v[6], .diverted = (unsigned long)v[7],
            .bad_lines = (unsigned long)v[8], .megabytes = (unsigned long)v[9],
            .shown = (unsigned)v[10], .seconds = (unsigned)v[11],
        };
        if (r->shown != st->n_files)
            return -1;
        r->verdict = gaudit_integrity_verdict(r);
        st->have_result = 1;
        return 0;
    }
    if (gaudit_sexpr_parse(line, "helper", summary, 4) == 0) {
        st->running = 0;
        if (*failed != 0 || !st->have_result)
            return emit_end(GAUDIT_RUN_FAILED);
        for (unsigned i = 0; i < st->n_files; i++) {
            gaudit_run_event ev = { .type = GAUDIT_RUN_EVENT_INTEGRITY_FILE, .file = st->files[i] };
            if (emit(&ev) != 0)
                return -1;
        }
        gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_INTEGRITY, .integrity = st->integrity };
        if (emit(&res) != 0)
            return -1;
        return emit_end(GAUDIT_RUN_OK);
    }
    return -1;
}

/* A line of the self-check: findings, the result, then the helper's
 * summary; read with the run events' own strict parser (the helper writes
 * the same lines), and passed on only when the run has succeeded. */
static int on_self_line(session_state *st, char *line, long long *failed,
                        const gaudit_sexpr_field *summary)
{
    gaudit_run_event ev;
    if (!st->have_result && gaudit_run_parse_line(line, &ev) == 0) {
        if (ev.type == GAUDIT_RUN_EVENT_SELF_FILE && st->n_self_files < GAUDIT_SELF_SHOWN) {
            st->self_files[st->n_self_files++] = ev.self_file;
            return 0;
        }
        if (ev.type == GAUDIT_RUN_EVENT_SELF_PROCESS && st->n_self_processes < GAUDIT_SELF_SHOWN) {
            st->self_processes[st->n_self_processes++] = ev.self_process;
            return 0;
        }
        if (ev.type == GAUDIT_RUN_EVENT_SELF && ev.self.files_shown == st->n_self_files
            && ev.self.processes_shown == st->n_self_processes) {
            st->self = ev.self;
            st->have_result = 1;
            return 0;
        }
        return -1;
    }
    if (gaudit_sexpr_parse(line, "helper", summary, 4) != 0)
        return -1;
    st->running = 0;
    if (*failed != 0 || !st->have_result)
        return emit_end(GAUDIT_RUN_FAILED);
    for (unsigned i = 0; i < st->n_self_files; i++) {
        gaudit_run_event e = { .type = GAUDIT_RUN_EVENT_SELF_FILE, .self_file = st->self_files[i] };
        if (emit(&e) != 0)
            return -1;
    }
    for (unsigned i = 0; i < st->n_self_processes; i++) {
        gaudit_run_event e = { .type = GAUDIT_RUN_EVENT_SELF_PROCESS,
                               .self_process = st->self_processes[i] };
        if (emit(&e) != 0)
            return -1;
    }
    gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_SELF, .self = st->self };
    if (emit(&res) != 0)
        return -1;
    return emit_end(GAUDIT_RUN_OK);
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
        if (emit_elevated(1) != 0)
            return -1;
        if (st->running && st->kind == RUN_ELEVATE) {
            st->running = 0;  /* that was all it asked for */
            return emit_end(GAUDIT_RUN_OK);
        }
        return 0;
    }
    if (gaudit_sexpr_parse(line, "helper-end", end, 1) == 0) {
        close_helper_input(st);  /* leaving: nothing more goes to it */
        return 0;
    }
    if (!st->running)
        return -1;  /* nothing else comes unasked */
    if (st->kind == RUN_INTEGRITY)
        return on_integrity_line(st, line, &failed, summary);
    if (st->kind == RUN_SELF_CHECK)
        return on_self_line(st, line, &failed, summary);
    if (is_exec_kind(st->kind)) {
        gaudit_run_event ev;
        if (!st->have_result && gaudit_run_parse_line(line, &ev) == 0
            && ev.type == GAUDIT_RUN_EVENT_EXEC) {
            st->have_result = 1;
            st->exec = ev.exec;
            return 0;
        }
        if (gaudit_sexpr_parse(line, "helper", summary, 4) != 0)
            return -1;
        st->running = 0;
        if (failed == 0 && st->have_result) {
            gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_EXEC, .exec = st->exec };
            if (emit(&res) != 0)
                return -1;
            return emit_end(GAUDIT_RUN_OK);
        }
        return emit_end(GAUDIT_RUN_FAILED);
    }
    if (is_vendor_kind(st->kind)) {
        gaudit_run_event ev;
        if (!st->have_result && gaudit_run_parse_line(line, &ev) == 0
            && ev.type == GAUDIT_RUN_EVENT_VENDOR
            && strcmp(ev.vendor.action, st->kind == RUN_VENDOR_VERIFY ? "verify" : "install") == 0) {
            st->have_result = 1;
            st->vendor = ev.vendor;
            return 0;
        }
        if (gaudit_sexpr_parse(line, "helper", summary, 4) != 0)
            return -1;
        st->running = 0;
        if (failed == 0 && st->have_result) {
            gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_VENDOR, .vendor = st->vendor };
            if (emit(&res) != 0)
                return -1;
            return emit_end(GAUDIT_RUN_OK);
        }
        return emit_end(GAUDIT_RUN_FAILED);
    }
    if (st->kind == RUN_CONF_ON || st->kind == RUN_CONF_REMOVE) {
        gaudit_run_event ev;
        if (!st->have_result && gaudit_run_parse_line(line, &ev) == 0
            && ev.type == GAUDIT_RUN_EVENT_CONF
            && strcmp(ev.conf.action, st->kind == RUN_CONF_ON ? "on" : "remove") == 0) {
            st->have_result = 1;
            st->conf = ev.conf;
            return 0;
        }
        if (gaudit_sexpr_parse(line, "helper", summary, 4) != 0)
            return -1;
        st->running = 0;
        if (failed == 0 && st->have_result) {
            gaudit_run_event res = { .type = GAUDIT_RUN_EVENT_CONF, .conf = st->conf };
            if (emit(&res) != 0)
                return -1;
            return emit_end(GAUDIT_RUN_OK);
        }
        return emit_end(GAUDIT_RUN_FAILED);
    }
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
        if (start_helper(st) != 0
            || (st->helper_line[0] != '\0' && send_helper(st, st->helper_line) != 0)) {
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

/* A command from the GUI: one of runs[], or "quit". */
static int on_gui_line(char *line, void *ctx)
{
    session_state *st = ctx;
    if (strcmp(line, "quit") == 0) {
        close_helper_input(st);  /* the helper ends its session */
        return 0;
    }
    int kind = -1;
    char helper_line[sizeof st->helper_line] = "";
    for (int i = 0; i < RUN_KINDS; i++)
        if (!takes_args(i) && strcmp(line, runs[i].request) == 0) {
            kind = i;
            if (runs[i].helper_cmd != NULL)
                snprintf(helper_line, sizeof helper_line, "%s", runs[i].helper_cmd);
        }
    /* "run reinstall <package> ..." and "run add-ppa <ppa>": arguments
     * plain for their operation (common/apt-ops.h), at most the helper's
     * limit; the helper checks again that they exist on this system. */
    for (int i = 0; kind < 0 && i < RUN_KINDS; i++) {
        size_t rl = strlen(runs[i].request);
        if (!takes_args(i) || strncmp(line, runs[i].request, rl) != 0 || line[rl] != ' ')
            continue;
        const char *op_name = runs[i].request + 4;  /* after "run " */
        const gaudit_apt_op *op = is_vendor_kind(i) ? NULL : gaudit_apt_op_find(op_name);
        char copy[sizeof st->helper_line];
        snprintf(copy, sizeof copy, "%s", line + rl + 1);
        const char *args[GAUDIT_APT_MAX_PACKAGES];
        size_t n = 0;
        int ok = op != NULL || is_vendor_kind(i);
        char *save = NULL;
        for (char *p = strtok_r(copy, " ", &save); ok && p != NULL; p = strtok_r(NULL, " ", &save))
            ok = n < GAUDIT_APT_MAX_PACKAGES && (args[n++] = p) != NULL;
        if (ok && i == RUN_VENDOR_VERIFY)
            ok = n == 3 && gaudit_vendor_verify_args_ok(args[0], args[1], args[2]);
        else if (ok && i == RUN_VENDOR_INSTALL)
            ok = (n == 1 || (n == 2 && strcmp(args[1], "anyway") == 0))
                 && gaudit_vendor_find(args[0]) != NULL;
        else if (ok)
            ok = gaudit_apt_op_args_ok(op, args, n);
        if (!ok)
            return -1;
        size_t used = (size_t)snprintf(helper_line, sizeof helper_line, "%s", op_name);
        for (size_t a = 0; a < n; a++) {
            if (used + strlen(args[a]) + 2 >= sizeof helper_line)
                return -1;
            used += (size_t)snprintf(helper_line + used, sizeof helper_line - used, " %s", args[a]);
        }
        snprintf(helper_line + used, sizeof helper_line - used, "\n");
        kind = i;
    }
    if (kind < 0 || st->running)
        return -1;  /* unknown, or one run at a time */
    if (kind == RUN_ELEVATE && st->started && st->to_helper >= 0)
        return emit_end(GAUDIT_RUN_OK);  /* already root, and not leaving */
    st->kind = kind;
    snprintf(st->helper_line, sizeof st->helper_line, "%s", helper_line);
    st->running = 1;
    st->overdue = 0;
    st->have_result = 0;
    st->n_files = 0;
    st->n_self_files = st->n_self_processes = 0;
    clock_gettime(CLOCK_MONOTONIC, &st->run_start);
    if (st->pid > 0 && st->to_helper < 0) {
        st->queued = 1;  /* the helper is ending; a new one follows */
        return 0;
    }
    if (st->pid <= 0 && start_helper(st) != 0) {
        st->running = 0;
        return emit_end(GAUDIT_RUN_FAILED);
    }
    if (st->helper_line[0] == '\0')
        return 0;  /* only the helper: its (helper-start ...) ends the run */
    /* Waits in the pipe until the helper runs (after the password). */
    if (send_helper(st, st->helper_line) != 0)
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
            long left = runs[st.kind].deadline_ms - elapsed_ms(&st.run_start);
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
    /* A known vendor package is in the Updates report's own group, not here. */
    if (gaudit_updates_vendor_of(gaudit_pkg_backend_default(), name, arch, group) != NULL
        || gaudit_updates_from_local(name, version)
        || gaudit_updates_companion_of(gaudit_pkg_backend_default(), name, arch) != NULL)
        return;
    st->count++;
    if (st->failed || st->shown >= GAUDIT_SOURCELESS_MAX_SHOWN)
        return;
    gaudit_sourceless_package p = { .group = group, .needed_by = -1, .manual = -1, .program = -1 };
    /* Names longer than the fields are counted but not sent. */
    if (snprintf(p.name, sizeof p.name, "%s", name) >= (int)sizeof p.name
        || snprintf(p.arch, sizeof p.arch, "%s", arch != NULL ? arch : "") >= (int)sizeof p.arch
        || snprintf(p.version, sizeof p.version, "%s", version) >= (int)sizeof p.version
        || snprintf(p.offered, sizeof p.offered, "%s", offered != NULL ? offered : "")
               >= (int)sizeof p.offered)
        return;
    /* What helps judge it, where the backend can tell. */
    gaudit_package_details d;
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    if (pkg->package_details != NULL && pkg->package_details(name, arch, &d) == GAUDIT_BACKEND_OK) {
        snprintf(p.replaced, sizeof p.replaced, "%s", d.replaced);
        snprintf(p.needed, sizeof p.needed, "%s", d.needed_names);
        p.needed_by = d.needed_by;
        p.manual = d.manual;
        p.installed = d.installed > 0 ? (long long)d.installed : 0;
        p.program = d.program;
        snprintf(p.built_for, sizeof p.built_for, "%s", d.built_for);
        snprintf(p.likely_source, sizeof p.likely_source, "%s", d.likely_source);
    }
    char line[2048];
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
    gaudit_updates_local_scan(pkg, "/var");
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
    /* Dies with the GUI that started it, however the GUI ends (window
     * closed, Ctrl-C, killed), so no search is left running without an
     * owner. Its own children die with it in turn. */
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != parent || parent == 1)
        return 1;
    /* The session starts pkexec, which is setuid: no_new_privs, and so a
     * seccomp filter, would keep it from ever becoming root. Every other
     * mode is confined, and what it starts inherits the filter. */
    if (argc == 2 && strcmp(argv[1], "session") == 0)
        return run_session();
    /* The network only where a click asked the service or a vendor
     * (John, 2026-11-16 and 2026-11-19). */
    int network = argc >= 3
                  && ((strcmp(argv[1], "updates") == 0
                       && (strcmp(argv[2], "latest") == 0 || strcmp(argv[2], "download") == 0))
                      || (strcmp(argv[1], "cloud") == 0 && strcmp(argv[2], "plain") == 0));
    if (gaudit_sandbox_restrict_net(network) != 0)
        return 1;
    if (argc == 1)
        return status_refresh();
    if (argc == 3 && strcmp(argv[1], "report") == 0)
        return gaudit_orchestrator_report(argv[2]);
    if ((argc == 4 || argc == 5) && strcmp(argv[1], "fix") == 0)
        return gaudit_private_files_fix(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    if (argc >= 3 && strcmp(argv[1], "secrets") == 0)
        return gaudit_private_files_secrets(argv[2], (const char *const *)argv + 3,
                                            (size_t)(argc - 3));
    if (argc >= 3 && strcmp(argv[1], "shared") == 0)
        return gaudit_shared_mode(argc, argv);
    if ((argc == 3 || argc == 5) && strcmp(argv[1], "cloud") == 0)
        return gaudit_cloud_mode(argc, argv);
    if (argc == 2 && strcmp(argv[1], "packages") == 0)
        return list_packages();
    if (argc == 3 && strcmp(argv[1], "updates") == 0)
        return gaudit_updates_mode(argv[2]);
    if (argc == 4 && strcmp(argv[1], "updates") == 0 && strcmp(argv[2], "latest") == 0)
        return gaudit_updates_latest(argv[3]);
    if (argc == 5 && strcmp(argv[1], "updates") == 0 && strcmp(argv[2], "download") == 0)
        return gaudit_updates_download(argv[3], argv[4]);
#if GAUDIT_DEVELOPER_BUILD
    /* Developer builds only: see the pages for missing software. */
    static const char pretend[] = "--pretend-missing=";
    if (argc == 2 && strncmp(argv[1], pretend, sizeof pretend - 1) == 0) {
        if (gaudit_capability_pretend_missing(argv[1] + sizeof pretend - 1) != 0)
            return 2;
        return status_refresh();
    }
#endif
    fputs("usage: gaudit-orchestrator [session | packages | updates quick | secrets quick|full [folder ...] | shared quick|full|check|merge|remove ... | cloud quick|full | report <plugin-id> | fix <id> <root> [path]]\n", stderr);
    return 2;
}
