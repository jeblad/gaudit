/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-engine: runs a plugin's report rule on its collected data.
 *
 *   gaudit-engine report <plugin-id>
 *   gaudit-engine selftest      tries what the sandbox forbids (confine.h)
 *
 * Reads one S-expression on stdin (at most ENGINE_MAX_INPUT bytes):
 *
 *   (input (system (host "...") (distro "...") (backend "..."))
 *          (collection <the collection's lines, in order>))
 *
 * and writes the report, one element per line:
 *
 *   (report (verdict V) (title MSG) (description MSG))   first
 *   (section (title MSG) (description MSG))
 *   (row (verdict V) (title MSG) (subtitle MSG) [(fix ID (item N))])
 *   (note MSG)
 *
 * MSG is (msg "text" (key value) ...), (msgn "one" "many" n (key value) ...)
 * or (text "plain"); texts are English msgids with {key} placeholders, which
 * the GUI translates and fills in. Nothing here translates, and nothing
 * here is trusted by the GUI: it parses the lines strictly.
 *
 * The rule comes from a fixed, compiled-in directory, never from the
 * caller: <rules dir>/<plugin-id>/report.scm. It is read into memory once
 * and evaluated with (ice-9 sandbox): only pure bindings, no I/O, with
 * time and allocation limits; why a rule failed goes to stderr, for the
 * developer (the GUI discards it). The data is read with `read`, never
 * evaluated, and the reader is never extended. The process runs as the
 * user with an empty environment, no_new_privs and the seccomp deny list
 * (no network), and then the engine's own filter: no files, no changes to
 * the filesystem, no sockets of any kind (so no D-Bus), no programs and no
 * processes. Guile has no bindings for any of it either. Until the signed manifest exists, outside developer builds
 * the rule file and its folder must be root-owned and not writable by
 * anyone else. Exit 0: report written; 1: no report (bad rule, bad input,
 * limits); 2: usage. */
#include "config.h"

#include "confine.h"
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <libguile.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Tests build the engine with their own rules (never in the installed one). */
#ifndef ENGINE_RULES_DIR
#define ENGINE_RULES_DIR GAUDIT_RULES_DIR
#endif

#define ENGINE_MAX_RULE  (64 * 1024)
#define ENGINE_MAX_INPUT (512 * 1024)

/* The driver: reads the rule's forms and the input (data only), evaluates
 * the rule in a sandbox, and writes the result one element per line. Any
 * error gives #f. */
static const char driver[] =
    "(use-modules (ice-9 sandbox))\n"
    "(lambda (rule-text input-text)\n"
    "  (define (read-all text)\n"
    "    (call-with-input-string text\n"
    "      (lambda (port)\n"
    "        (let loop ((acc '()))\n"
    "          (let ((x (read port)))\n"
    "            (if (eof-object? x) (reverse acc) (loop (cons x acc))))))))\n"
    "  (catch #t\n"
    "    (lambda ()\n"
    "      (let ((forms (read-all rule-text))\n"
    "            (inputs (read-all input-text)))\n"
    "        (and (= (length inputs) 1)\n"
    "             (let ((result (eval-in-sandbox\n"
    "                             `(let ()\n"
    "                                (define (G_ s) s)\n"
    "                                (define (N_ one many) (list one many))\n"
    "                                ,@forms\n"
    "                                (report (quote ,(car inputs))))\n"
    "                             #:time-limit 2\n"
    "                             #:allocation-limit 100000000\n"
    "                             #:bindings all-pure-bindings)))\n"
    "               (and (list? result) (pair? result)\n"
    "                    (call-with-output-string\n"
    "                      (lambda (out)\n"
    "                        (for-each (lambda (x) (write x out) (newline out)) result))))))))\n"
    "    (lambda (key . args)\n"
    "      (write key (current-error-port)) (display \" \" (current-error-port))\n"
    "      (write args (current-error-port)) (newline (current-error-port))\n"
    "      #f)))\n";

static int plain_id(const char *id)
{
    size_t n = strlen(id);
    if (n == 0 || n > 64)
        return 0;
    for (const char *p = id; *p != '\0'; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-'))
            return 0;
    return strstr(id, "..") == NULL && id[0] != '.';
}

#if !GAUDIT_DEVELOPER_BUILD
/* Root-owned and writable by root only. */
static int trusted(const struct stat *sb)
{
    return sb->st_uid == 0 && (sb->st_mode & 022) == 0;
}
#endif

/* The rule file into memory, once. NULL on any problem. */
static char *read_rule(const char *id)
{
    char dir[1024], path[1100];
    if (snprintf(dir, sizeof dir, "%s/%s", ENGINE_RULES_DIR, id) >= (int)sizeof dir
        || snprintf(path, sizeof path, "%s/report.scm", dir) >= (int)sizeof path)
        return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    struct stat sb, dsb;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size > ENGINE_MAX_RULE
        || stat(dir, &dsb) != 0) {
        close(fd);
        return NULL;
    }
#if !GAUDIT_DEVELOPER_BUILD
    if (!trusted(&sb) || !trusted(&dsb)) {
        close(fd);
        return NULL;
    }
#endif
    char *buf = malloc((size_t)sb.st_size + 1);
    size_t got = 0;
    while (buf != NULL && got < (size_t)sb.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)sb.st_size - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (buf == NULL || got != (size_t)sb.st_size) {
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    return memchr(buf, '\0', got) == NULL ? buf : (free(buf), NULL);
}

/* stdin into memory, at most ENGINE_MAX_INPUT bytes; invalid UTF-8 replaced, so
 * Guile always reads it (names on disk need not be UTF-8; what is shown is
 * for display only, and fixes never take a path from the report). */
static char *read_input(void)
{
    char *buf = malloc(ENGINE_MAX_INPUT + 1);
    size_t got = 0;
    while (buf != NULL) {
        ssize_t n = read(STDIN_FILENO, buf + got, ENGINE_MAX_INPUT + 1 - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
        if (got > ENGINE_MAX_INPUT) {
            free(buf);
            return NULL;
        }
    }
    if (buf == NULL)
        return NULL;
    buf[got] = '\0';
    if (memchr(buf, '\0', got) != NULL) {
        free(buf);
        return NULL;
    }
    for (size_t i = 0; i < got;) {
        unsigned char c = (unsigned char)buf[i];
        size_t len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3
                   : (c & 0xf8) == 0xf0 ? 4 : 0;
        int ok = len > 0 && i + len <= got && !(len == 2 && c < 0xc2);
        for (size_t k = 1; ok && k < len; k++)
            ok = ((unsigned char)buf[i + k] & 0xc0) == 0x80;
        if (!ok) {
            buf[i++] = '?';
            continue;
        }
        i += len;
    }
    return buf;
}

typedef struct {
    const char *rule;
    const char *input;
    int status;
} job;

static void *run(void *data)
{
    job *j = data;
    SCM proc = scm_c_eval_string(driver);
    /* Everything Guile needs is loaded now; from here, no network, no
     * files, no processes. */
    if (gaudit_sandbox_restrict() != 0 || gaudit_engine_confine() != 0)
        return NULL;
    if (j->rule == NULL) {
        j->status = gaudit_engine_selftest();
        return NULL;
    }
    SCM out = scm_call_2(proc, scm_from_utf8_string(j->rule), scm_from_utf8_string(j->input));
    if (!scm_is_string(out))
        return NULL;
    char *text = scm_to_utf8_string(out);
    size_t len = strlen(text);
    j->status = fwrite(text, 1, len, stdout) == len && fflush(stdout) == 0 ? 0 : 1;
    free(text);
    return NULL;
}

int main(int argc, char *argv[])
{
    /* Nothing from the caller's environment reaches Guile (GUILE_LOAD_PATH
     * and friends), and nothing is compiled into the user's cache. */
    if (clearenv() != 0 || setenv("GUILE_AUTO_COMPILE", "0", 1) != 0)
        return 2;
    if (argc == 2 && strcmp(argv[1], "selftest") == 0) {
        job self = { .status = 1 };
        scm_with_guile(run, &self);
        return self.status;
    }
    if (argc != 3 || strcmp(argv[1], "report") != 0 || !plain_id(argv[2])) {
        fputs("usage: gaudit-engine report <plugin-id>\n", stderr);
        return 2;
    }
    job j = { .status = 1 };
    char *rule = read_rule(argv[2]);
    char *input = read_input();
    if (rule == NULL || input == NULL) {
        free(rule);
        free(input);
        return 1;
    }
    j.rule = rule;
    j.input = input;
    scm_with_guile(run, &j);
    free(rule);
    free(input);
    return j.status;
}
