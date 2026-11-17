/* SPDX-License-Identifier: GPL-3.0-only */
#include "selfcheck.h"

#include "gaudit-environ.h"

#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SHOWN 40
#define MAX_READ  (1 << 20)

/* A plain text for a quoted field: printable ASCII, no quote or backslash. */
static void plain(const char *in, char *out, size_t len)
{
    size_t n = 0;
    for (const char *c = in; *c != '\0' && n + 1 < len; c++)
        out[n++] = (*c >= 0x20 && *c < 0x7f && *c != '"' && *c != '\\') ? *c : '?';
    out[n] = '\0';
}

static char *read_small(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    char *buf = malloc(MAX_READ + 1);
    size_t got = 0;
    while (buf != NULL && got < MAX_READ) {
        ssize_t n = read(fd, buf + got, MAX_READ - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (buf != NULL) {
        buf[got] = '\0';
        *len = got;
    }
    return buf;
}

/* --- The manifest's version, kept ----------------------------------------- */

static unsigned long long seen_version(const char *state)
{
    size_t len = 0;
    char *text = state != NULL ? read_small(state, &len) : NULL;
    unsigned long long v = text != NULL ? strtoull(text, NULL, 10) : 0;
    free(text);
    return v;
}

static void keep_version(const char *state, unsigned long long v)
{
    if (state == NULL)
        return;
    char tmp[512], text[32];
    snprintf(tmp, sizeof tmp, "%s.new", state);
    snprintf(text, sizeof text, "%llu\n", v);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    int ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text) && fsync(fd) == 0;
    close(fd);
    if (!ok || rename(tmp, state) != 0)
        unlink(tmp);
}

/* --- Files ------------------------------------------------------------------ */

typedef struct {
    FILE *out;
    unsigned shown, changed, missing, extra;
    const gaudit_manifest *m;
} file_ctx;

static void file_line(file_ctx *c, const char *path, const char *problem)
{
    if (c->shown >= MAX_SHOWN)
        return;
    char p[256];  /* a text field holds at most 255 bytes */
    plain(path, p, sizeof p);
    fprintf(c->out, "(self-file (path \"%s\") (problem \"%s\"))\n", p, problem);
    c->shown++;
}

static int listed(const gaudit_manifest *m, const char *path)
{
    for (size_t i = 0; i < m->n_files; i++)
        if (strcmp(m->files[i].path, path) == 0)
            return 1;
    return 0;
}

/* Every plain file below dir (a few levels, never through a link) that the
 * manifest does not list. */
static void extras(file_ctx *c, const char *dir, int depth)
{
    if (depth > 4)
        return;
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char path[512];
        if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >= sizeof path)
            continue;
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            extras(c, path, depth + 1);
        } else if (!listed(c->m, path)) {
            c->extra++;
            file_line(c, path, "extra");
        }
    }
    closedir(d);
}

/* --- Processes -------------------------------------------------------------- */

static unsigned processes_shown;  /* lines written in this check, at most MAX_SHOWN */

static void process_line(FILE *out, const char *which, const char *problem, const char *detail)
{
    if (processes_shown >= MAX_SHOWN)
        return;
    processes_shown++;
    char d[256];
    plain(detail, d, sizeof d);
    fprintf(out, "(self-process (which \"%s\") (problem \"%s\") (detail \"%s\"))\n", which, problem, d);
}

static int code_dir_ok(const gaudit_selfcheck_env *env, const char *path)
{
    for (size_t i = 0; i < env->n_code_dirs; i++)
        if (strncmp(path, env->code_dirs[i], strlen(env->code_dirs[i])) == 0)
            return 1;
    return 0;
}

int gaudit_selfcheck_process(const gaudit_selfcheck_env *env, pid_t pid, const char *which,
                             const char *exe, FILE *out)
{
    char path[64], target[512];
    int problems = 0;
    /* The program it runs. */
    snprintf(path, sizeof path, "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(path, target, sizeof target - 1);
    if (n < 0) {
        process_line(out, which, "gone", "");
        return 1;
    }
    target[n] = '\0';
    /* The kernel names the real file: compare with where the expected path
     * really leads (a link in the way, such as /lib to /usr/lib). */
    char real[PATH_MAX];
    if (exe != NULL && realpath(exe, real) == NULL)
        snprintf(real, sizeof real, "%s", exe);
    if (exe != NULL && strcmp(target, real) != 0) {
        process_line(out, which, "exe", target);
        problems++;
    }
    /* No variable that loads other code. */
    snprintf(path, sizeof path, "/proc/%d/environ", (int)pid);
    size_t len = 0;
    char *env_text = read_small(path, &len);
    for (size_t i = 0; env_text != NULL && i < len;) {
        const char *entry = env_text + i;
        size_t el = strnlen(entry, len - i);
        if (gaudit_environ_unwanted(entry)) {
            char name[128];
            snprintf(name, sizeof name, "%.*s", (int)strcspn(entry, "="), entry);
            process_line(out, which, "env", name);
            problems++;
        }
        i += el + 1;
    }
    free(env_text);
    /* No executable code from outside the system's folders, nor from a file
     * others could change. */
    snprintf(path, sizeof path, "/proc/%d/maps", (int)pid);
    char *maps = read_small(path, &len);
    char last[512] = "";
    for (char *line = maps, *next; line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        char perms[8] = "";
        int at = 0;
        if (sscanf(line, "%*s %7s %*s %*s %*s %n", perms, &at) != 1 || strchr(perms, 'x') == NULL
            || at == 0)
            continue;
        const char *file = line + at;
        if (file[0] != '/' || strcmp(file, last) == 0)
            continue;  /* anonymous, [vdso] and the like */
        snprintf(last, sizeof last, "%s", file);
        struct stat st;
        int bad = !code_dir_ok(env, file) || strstr(file, " (deleted)") != NULL
                  || stat(file, &st) != 0
                  || (!env->developer && (st.st_uid != 0 || (st.st_mode & 022) != 0));
        if (bad) {
            process_line(out, which, "maps", file);
            problems++;
        }
    }
    free(maps);
    return problems;
}

/* The parent of pid, from /proc/<pid>/stat; 0 unknown. */
static pid_t parent_of(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    size_t len = 0;
    char *text = read_small(path, &len);
    pid_t pp = 0;
    /* The name in parentheses may hold anything: read after its last ')'. */
    char *close_paren = text != NULL ? strrchr(text, ')') : NULL;
    if (close_paren != NULL) {
        int v = 0;
        if (sscanf(close_paren + 1, " %*c %d", &v) == 1)
            pp = (pid_t)v;
    }
    free(text);
    return pp;
}

/* --- The whole check -------------------------------------------------------- */

void gaudit_selfcheck(const gaudit_selfcheck_env *env, FILE *out)
{
    gaudit_manifest m = { 0 };
    const char *status;
    processes_shown = 0;
    file_ctx c = { .out = out, .m = &m };
    unsigned long long seen = seen_version(env->state_file);
    unsigned long long min = seen > env->min_version ? seen : env->min_version;
    size_t mlen = 0, slen = 0;
    char *mtext = read_small(env->manifest_path, &mlen);
    char *sig = read_small(env->sig_path, &slen);
    if (env->n_keys == 0) {
        status = "no-key";  /* a build without gAudit's key: a developer build */
    } else if (mtext == NULL || sig == NULL) {
        status = "missing";
    } else {
        gaudit_manifest_status st = gaudit_manifest_load((const unsigned char *)mtext, mlen, sig,
                                                         env->keys, env->n_keys, env->now, min, &m);
        status = gaudit_manifest_status_name(st);
        if (st == GAUDIT_MANIFEST_OK) {
            if (m.version > seen)
                keep_version(env->state_file, m.version);
            for (size_t i = 0; i < m.n_files; i++) {
                gaudit_manifest_file_status fs = gaudit_manifest_check_file(&m.files[i]);
                if (fs == GAUDIT_MANIFEST_FILE_CHANGED) {
                    c.changed++;
                    file_line(&c, m.files[i].path, "changed");
                } else if (fs == GAUDIT_MANIFEST_FILE_MISSING) {
                    c.missing++;
                    file_line(&c, m.files[i].path, "missing");
                }
            }
            for (size_t i = 0; i < env->n_dirs; i++)
                extras(&c, env->dirs[i], 0);
        }
    }
    free(mtext);
    free(sig);
    /* Who asked, and the GUI above it. */
    unsigned processes = 0;
    int process_problems = 0;
    if (env->orchestrator > 1) {
        processes++;
        process_problems += gaudit_selfcheck_process(env, env->orchestrator, "orchestrator",
                                                     env->orchestrator_exe, out);
        pid_t gui = parent_of(env->orchestrator);
        if (gui > 1) {
            processes++;
            process_problems += gaudit_selfcheck_process(env, gui, "gui", env->gui_exe, out);
        }
    }
    fprintf(out,
            "(self (manifest \"%s\") (version %llu) (files %zu) (changed %u) (missing %u) (extra %u)"
            " (files-shown %u) (processes %u) (process-problems %d) (processes-shown %u))\n",
            status, m.version, m.n_files, c.changed, c.missing, c.extra, c.shown, processes,
            process_problems, processes_shown);
    gaudit_manifest_free(&m);
}
