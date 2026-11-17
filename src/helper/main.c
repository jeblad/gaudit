/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-helper: privileged helper, started via pkexec.
 *
 *   gaudit-helper selftest | firewall | integrity | session
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
 *   integrity every deb package's files against dpkg's md5sums (root with
 *             CAP_DAC_READ_SEARCH only, several threads, up to 15 minutes):
 *             up to 40 (integrity-file ...) lines, then (integrity ...)
 *   automatic-updates-on, automatic-updates-remove
 *             write or remove gAudit's own apt drop-in for automatic
 *             updates (root without any capability: the folders are
 *             root's own), only as conf-write.h allows: one
 *             (conf (template ...) (action ...) (result ...)) line
 *   session   keeps the rights for more commands (one per line on stdin:
 *             a command name, or "quit") within the lease of lease.h, and
 *             ends with (helper-end (reason ...)): idle, cap, quit, eof or
 *             bad-command. An unknown command ends the session.
 *
 * Never translates output: it runs as root, and its output is a
 * language-neutral protocol. Verifying the signed manifest, inspecting the
 * other gaudit processes and the root-owned log come later. */
#include "config.h"

#include "apt.h"
#include "vendor-pkg.h"
#include "vendor.h"
#include "selfcheck.h"
#include "manifest-keys.h"
#include "automatic.h"
#include "integrity.h"
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
 * and collect less than len bytes within timeout_ms.
 * 0 on success (buf holds the output), -1 otherwise. */
static int run_check(const gaudit_sandbox *spec, check_fn fn, void *ctx, long timeout_ms,
                     char *buf, size_t len)
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
        long left = timeout_ms - elapsed_ms(&start);
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

/* --- integrity ------------------------------------------------------------ */

#define INTEGRITY_SHOWN 40

static const char *const kind_names[] = { "changed", "missing", "unreadable" };

/* Printable ASCII only, '"' and '\\' escaped; 0 if it does not fit or has
 * anything else (the finding is then counted but not listed). */
static int quote(const char *in, char *out, size_t len)
{
    size_t n = 0;
    out[n++] = '"';
    for (const char *c = in; *c != '\0'; c++) {
        if (*c < 0x20 || *c > 0x7e || n + 3 >= len)
            return 0;
        if (*c == '"' || *c == '\\')
            out[n++] = '\\';
        out[n++] = *c;
    }
    out[n++] = '"';
    out[n] = '\0';
    return 1;
}

static void on_integrity(gaudit_integrity_kind kind, const char *package, const char *path,
                         void *ctx)
{
    unsigned *shown = ctx;
    char pkg[130], file[258];  /* what the receiving parsers accept */
    if (*shown >= INTEGRITY_SHOWN || !quote(package, pkg, sizeof pkg)
        || !quote(path, file, sizeof file))
        return;
    printf("(integrity-file (kind %s) (package %s) (path %s))\n", kind_names[kind], pkg, file);
    (*shown)++;
}

static void integrity(void *ctx)
{
    (void)ctx;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    /* Past about eight threads the disk sets the pace, not the CPU. */
    gaudit_integrity_paths paths = {
        .root = "", .info_dir = "/var/lib/dpkg/info", .diversions = "/var/lib/dpkg/diversions",
        .cfg_file = "/etc/dpkg/dpkg.cfg", .cfg_dir = "/etc/dpkg/dpkg.cfg.d",
        .threads = cpus < 1 ? 1 : cpus > 8 ? 8 : (unsigned)cpus,
    };
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned shown = 0;
    gaudit_integrity_result r;
    if (gaudit_integrity_scan(&paths, &r, on_integrity, &shown) != 0)
        _exit(1);
    printf("(integrity (packages %u) (files %lu) (checked %lu) (changed %lu) (missing %lu)"
           " (unreadable %lu) (excluded %lu) (diverted %lu) (bad-lines %lu) (megabytes %llu)"
           " (shown %u) (seconds %ld))\n",
           r.packages, r.files, r.checked, r.changed, r.missing, r.unreadable, r.excluded,
           r.diverted, r.bad_lines, r.bytes / 1000000, shown, elapsed_ms(&start) / 1000);
}

/* --- configuration -------------------------------------------------------- */

static const gaudit_conf_env system_env = { .root = "/", .register_dir = "var/lib/gaudit", .owner = 0 };

static void automatic_on(void *ctx)
{
    (void)ctx;
    printf("(conf (template \"%s\") (action \"on\") (result \"%s\"))\n", GAUDIT_AUTOMATIC_TEMPLATE,
           gaudit_conf_result_name(gaudit_automatic_updates_on(&system_env)));
}

static void automatic_remove(void *ctx)
{
    (void)ctx;
    printf("(conf (template \"%s\") (action \"remove\") (result \"%s\"))\n", GAUDIT_AUTOMATIC_TEMPLATE,
           gaudit_conf_result_name(gaudit_automatic_updates_remove(&system_env)));
}

/* --- apt, on request ---------------------------------------------------- */

/* The arguments of a "reinstall" or "add-ppa" command, checked in apt.c
 * again before use. */
static char *exec_packages[GAUDIT_APT_MAX_PACKAGES];
static size_t n_exec_packages;

static void apt_exec(void *ctx)
{
    const char *op = ctx;
    int status = gaudit_apt_run(op, exec_packages, n_exec_packages);
    printf("(exec (op \"%s\") (status %d))\n", op, status < 0 ? 255 : status > 255 ? 255 : status);
}

/* --- A known vendor package, on request ---------------------------------- */

static const gaudit_vendor_env vendor_env = {
    .cache_dir = "/var/cache/gaudit/vendor",
    .keys_dir = GAUDIT_VENDOR_KEYS_DIR,
    .owner = 0,
#if GAUDIT_DEVELOPER_BUILD
    .check_key_owner = 0,  /* the build tree's key file */
#else
    .check_key_owner = 1,
#endif
    .sqv = "/usr/bin/sqv",
    .weak_policy = GAUDIT_VENDOR_KEYS_DIR "/sha1-only.toml",
    .dpkg_deb = "/usr/bin/dpkg-deb",
    .dpkg_query = "/usr/bin/dpkg-query",
    .dpkg = "/usr/bin/dpkg",
};

/* The arguments of "vendor-verify <id> <version> <path>" or
 * "vendor-install <id> [anyway]", checked when the command is read. */
static char *vendor_args[3];
static size_t n_vendor_args;

static void vendor_report(const char *action, const char *id, const gaudit_vendor_outcome *o)
{
    printf("(vendor (id \"%s\") (action \"%s\") (result \"%s\") (version \"%s\") (hash \"%s\"))\n",
           id, action, o->result, o->version, o->hash);
}

static void vendor_verify(void *ctx)
{
    (void)ctx;
    gaudit_vendor_outcome o;
    gaudit_vendor_verify(&vendor_env, vendor_args[0], vendor_args[1], vendor_args[2], &o);
    vendor_report("verify", vendor_args[0], &o);
}

static void vendor_install(void *ctx)
{
    (void)ctx;
    gaudit_vendor_outcome o;
    gaudit_vendor_install(&vendor_env, vendor_args[0],
                          n_vendor_args == 2 && strcmp(vendor_args[1], "anyway") == 0, &o);
    vendor_report("install", vendor_args[0], &o);
}

static int vendor_args_ok(const char *name)
{
    if (strcmp(name, "vendor-verify") == 0)
        return n_vendor_args == 3
               && gaudit_vendor_verify_args_ok(vendor_args[0], vendor_args[1], vendor_args[2]);
    return gaudit_vendor_find(vendor_args[0]) != NULL
           && (n_vendor_args == 1 || (n_vendor_args == 2 && strcmp(vendor_args[1], "anyway") == 0));
}

/* --- gAudit checking itself -------------------------------------------- */

/* Who asked: the helper's parent (pkexec runs the helper in its own place),
 * taken before anything else. */
static pid_t asker;

static void self_check(void *ctx)
{
    (void)ctx;
    gaudit_manifest_key keys[4];
    size_t n_keys = 0;
    for (size_t i = 0; gaudit_manifest_key_texts[i] != NULL && n_keys < 4; i++)
        if (gaudit_manifest_key_parse(gaudit_manifest_key_texts[i], &keys[n_keys]) == 0)
            n_keys++;
    static const char *const dirs[] = { GAUDIT_RULES_DIR, GAUDIT_VENDOR_KEYS_DIR, GAUDIT_PKGLIBEXECDIR };
#if GAUDIT_DEVELOPER_BUILD
    static const char *const code_dirs[] = { "/usr/", "/lib", GAUDIT_PREFIX "/", PROJECT_BINARY_DIR "/" };
#else
    static const char *const code_dirs[] = { "/usr/", "/lib" };
#endif
    mkdir("/var/lib/gaudit", 0755);
    gaudit_selfcheck_env env = {
        .manifest_path = GAUDIT_MANIFEST_PATH, .sig_path = GAUDIT_MANIFEST_PATH ".minisig",
        .keys = keys, .n_keys = n_keys, .min_version = GAUDIT_MANIFEST_MIN_VERSION,
        .state_file = "/var/lib/gaudit/manifest-version",
        .dirs = dirs, .n_dirs = sizeof dirs / sizeof dirs[0],
        .orchestrator = asker, .orchestrator_exe = GAUDIT_ORCHESTRATOR_PATH,
        .gui_exe = GAUDIT_SELF_GUI_PATH,
        .code_dirs = code_dirs, .n_code_dirs = sizeof code_dirs / sizeof code_dirs[0],
        .developer = GAUDIT_DEVELOPER_BUILD, .now = (int64_t)time(NULL),
    };
    gaudit_selfcheck(&env, stdout);
}

/* --- The root-owned log -------------------------------------------------- */

/* One line per command the helper ran, in a log only root can write, so
 * what the user's side keeps can be compared with it afterwards. Readable
 * by all: it names commands and counts, nothing private. */
static void log_command(long caller, const char *name, int ok, int failed)
{
    mkdir("/var/log/gaudit", 0755);
    int fd = open("/var/log/gaudit/helper.log",
                  O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0) {
        close(fd);
        return;
    }
    fchmod(fd, 0644);
    char when[32] = "";
    time_t now = time(NULL);
    struct tm tm;
    if (gmtime_r(&now, &tm) != NULL)
        strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tm);
    char line[256];
    int n = snprintf(line, sizeof line, "%s caller=%ld command=%s ok=%d failed=%d\n", when, caller,
                     name, ok, failed);
    if (n > 0 && (size_t)n < sizeof line && write(fd, line, (size_t)n) < 0) {
        /* nothing to do: the command's own result still goes to the caller */
    }
    close(fd);
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
    long timeout_ms;    /* 0: CHECK_TIMEOUT_MS */
    size_t max_output;  /* 0: MAX_CHECK_OUTPUT */
} check_def;

static const cap_value_t read_caps[] = { CAP_DAC_READ_SEARCH };
static const cap_value_t net_caps[] = { CAP_NET_ADMIN };

static const check_def selftest_checks[] = {
    { "nobody",          { .to_nobody = 1 },                                  selftest, 0, 0 },
    { "dac-read-search", { .to_nobody = 0, .caps = read_caps, .n_caps = 1 }, selftest, 0, 0 },
};
static const check_def firewall_checks[] = {
    { "firewall",        { .to_nobody = 0, .caps = net_caps, .n_caps = 1 },  firewall, 0, 0 },
};

/* Root, but no capability: writing in root's own folders needs none. */
static const check_def automatic_on_checks[] = {
    { "automatic-updates-on",     { .to_nobody = 0 }, automatic_on, 0, 0 },
};
static const check_def automatic_remove_checks[] = {
    { "automatic-updates-remove", { .to_nobody = 0 }, automatic_remove, 0, 0 },
};

/* A system tool as root, as with sudo: no sandbox (apt needs the network,
 * every capability and its maintainer scripts). The operations are fixed
 * (apt.c), and an upgrade can take a long time. */
#define APT_TIMEOUT_MS (45 * 60 * 1000L)
static const check_def apt_update_checks[] = {
    { "apt-update",        { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
static const check_def apt_upgrade_checks[] = {
    { "apt-upgrade",       { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
static const check_def apt_upgrade_update_checks[] = {
    { "apt-upgrade-update", { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
static const check_def apt_timers_checks[] = {
    { "enable-apt-timers", { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
static const check_def apt_reinstall_checks[] = {
    { "reinstall",         { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
static const check_def apt_add_ppa_checks[] = {
    { "add-ppa",           { .unconfined = 1 }, apt_exec, APT_TIMEOUT_MS, 0 },
};
/* Copying the user's download needs to read their files; checking it runs
 * gpgv and dpkg-deb as root without other capabilities, in the sandbox.
 * Installing is apt, as root like any apt step. */
static const check_def vendor_verify_checks[] = {
    { "vendor-verify",  { .to_nobody = 0, .caps = read_caps, .n_caps = 1 }, vendor_verify,
      10 * 60 * 1000L, 0 },
};
/* Reading the orchestrator's and the GUI's environment and memory map
 * takes CAP_SYS_PTRACE (they are the user's); reading gAudit's files,
 * CAP_DAC_READ_SEARCH. */
static const cap_value_t self_caps[] = { CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH };
static const check_def self_check_checks[] = {
    { "self-check", { .to_nobody = 0, .caps = self_caps, .n_caps = 2 }, self_check,
      2 * 60 * 1000L, 16384 },
};
static const check_def vendor_install_checks[] = {
    { "vendor-install", { .unconfined = 1 }, vendor_install, APT_TIMEOUT_MS, 0 },
};

/* Reading every package file takes time: half a minute on a fast disk,
 * several minutes on a slow one. */
static const check_def integrity_checks[] = {
    { "integrity",       { .to_nobody = 0, .caps = read_caps, .n_caps = 1 }, integrity,
      15 * 60 * 1000L, 16384 },
};

static const struct {
    const char *name;
    const check_def *checks;
    size_t n_checks;
} commands[] = {
    { "selftest", selftest_checks, sizeof selftest_checks / sizeof selftest_checks[0] },
    { "firewall", firewall_checks, sizeof firewall_checks / sizeof firewall_checks[0] },
    { "integrity", integrity_checks, sizeof integrity_checks / sizeof integrity_checks[0] },
    { "automatic-updates-on", automatic_on_checks, 1 },
    { "automatic-updates-remove", automatic_remove_checks, 1 },
    { "apt-update", apt_update_checks, 1 },
    { "apt-upgrade", apt_upgrade_checks, 1 },
    { "apt-upgrade-update", apt_upgrade_update_checks, 1 },
    { "enable-apt-timers", apt_timers_checks, 1 },
    { "reinstall", apt_reinstall_checks, 1 },
    { "add-ppa", apt_add_ppa_checks, 1 },
    { "vendor-verify", vendor_verify_checks, 1 },
    { "vendor-install", vendor_install_checks, 1 },
    { "self-check", self_check_checks, 1 },
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
        size_t len = def->max_output > 0 ? def->max_output : MAX_CHECK_OUTPUT;
        char *out = malloc(len);
        if (out != NULL
            && run_check(&def->spec, def->fn, (void *)def->variant,
                         def->timeout_ms > 0 ? def->timeout_ms : CHECK_TIMEOUT_MS, out, len) == 0) {
            fputs(out, stdout);
            ok++;
        } else {
            failed++;
        }
        free(out);
    }
    log_command(caller, commands[i].name, ok, failed);
    printf("(helper (version 1) (caller %ld) (checks-ok %d) (checks-failed %d))\n",
           caller, ok, failed);
    return fflush(stdout) == 0 && failed == 0 ? 0 : 1;
}

/* --- Session ------------------------------------------------------------- */

/* A command and, for "reinstall" and "add-ppa" only, its arguments. */
#define MAX_COMMAND 4096

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
        /* "reinstall <package> ..." and "add-ppa <ppa>" are the only
         * commands with arguments: plain names of installed packages, or
         * a PPA the release upgrade switched off, checked here and again
         * before the tool is run. Anything else is a single word. */
        n_exec_packages = 0;
        n_vendor_args = 0;
        char *save = NULL;
        char *name = strtok_r(line, " ", &save);
        int i = name != NULL ? find_command(name) : -1;
        /* A known vendor package: its own arguments, checked here and
         * again where they are used. */
        if (i >= 0 && (strcmp(name, "vendor-verify") == 0 || strcmp(name, "vendor-install") == 0)) {
            int bad_args = 0;
            for (char *arg = strtok_r(NULL, " ", &save); !bad_args && arg != NULL;
                 arg = strtok_r(NULL, " ", &save))
                bad_args = n_vendor_args >= 3 || !(vendor_args[n_vendor_args++] = arg);
            if (bad_args || n_vendor_args == 0 || !vendor_args_ok(name)) {
                reason = "bad-command";
                status = 1;
                break;
            }
            run_command(i, caller);
            gaudit_lease_renew(&lease, gaudit_lease_now());
            continue;
        }
        const gaudit_apt_op *op = i >= 0 ? gaudit_apt_op_find(name) : NULL;
        int bad = i < 0;
        for (char *arg = strtok_r(NULL, " ", &save); !bad && arg != NULL; arg = strtok_r(NULL, " ", &save))
            bad = op == NULL || op->args == GAUDIT_APT_ARGS_NONE
                  || n_exec_packages >= GAUDIT_APT_MAX_PACKAGES || !gaudit_apt_arg_ok(op, arg)
                  || !(exec_packages[n_exec_packages++] = arg);
        if (!bad && op != NULL
            && !gaudit_apt_op_args_ok(op, (const char *const *)exec_packages, n_exec_packages))
            bad = 1;
        if (bad) {
            reason = "bad-command";
            status = 1;
            break;
        }
        /* A run under way when the cap is reached may finish. */
        run_command(i, caller);
        gaudit_lease_renew(&lease, gaudit_lease_now());
    }
    /* Nothing checked for installing outlives the session. */
    gaudit_vendor_clean(&vendor_env);
    printf("(helper-end (reason \"%s\"))\n", reason);
    return fflush(stdout) == 0 ? status : 1;
}

/* --- main ----------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    int cmd = argc == 2 ? find_command(argv[1]) : -1;
    /* Commands with arguments come only through a session. */
    if (cmd >= 0 && (strncmp(argv[1], "vendor-", 7) == 0 || strcmp(argv[1], "reinstall") == 0
                     || strcmp(argv[1], "add-ppa") == 0))
        cmd = -1;
    int is_session = argc == 2 && strcmp(argv[1], "session") == 0;
    if (cmd < 0 && !is_session) {
        fputs("usage: gaudit-helper selftest | firewall | integrity | automatic-updates-on"
              " | automatic-updates-remove | session\n", stderr);
        return 2;
    }
    if (getuid() != 0 || geteuid() != 0) {
        fputs("gaudit-helper: must run as root (through pkexec)\n", stderr);
        return 1;
    }

    asker = getppid();
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
