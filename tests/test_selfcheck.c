/* SPDX-License-Identifier: GPL-3.0-only */
/* gAudit checking itself, without root: a manifest signed here, with one
 * file changed, one missing and one extra in a folder of its own; and two
 * processes, one started with GTK_MODULES set, one running a copy of a
 * program from a folder the user owns. */
#define _GNU_SOURCE
#include "selfcheck.h"
#include "gaudit/run.h"

#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

static char dir[] = "/tmp/gaudit-selfcheck-XXXXXX";

static void put(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

/* Signs text as minisign does ("ED"), into sig. */
static void sign(const unsigned char *sk, const unsigned char id[8], const char *text, char *sig, size_t len)
{
    unsigned char raw[74] = { 'E', 'D' }, h[64], both[64 + 8], global[64];
    memcpy(raw + 2, id, 8);
    crypto_generichash(h, sizeof h, (const unsigned char *)text, strlen(text), NULL, 0);
    crypto_sign_detached(raw + 10, NULL, h, sizeof h, sk);
    memcpy(both, raw + 10, 64);
    memcpy(both + 64, "test 123", 8);
    crypto_sign_detached(global, NULL, both, sizeof both, sk);
    char l2[200], l4[200];
    sodium_bin2base64(l2, sizeof l2, raw, sizeof raw, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(l4, sizeof l4, global, sizeof global, sodium_base64_VARIANT_ORIGINAL);
    snprintf(sig, len, "untrusted comment: s\n%s\ntrusted comment: test 123\n%s\n", l2, l4);
}

/* Every line the helper writes is a run event the orchestrator accepts. */
static void all_parse(const char *out)
{
    char *copy = strdup(out), *save = NULL;
    int lines = 0;
    for (char *l = strtok_r(copy, "\n", &save); l != NULL; l = strtok_r(NULL, "\n", &save)) {
        gaudit_run_event ev;
        lines++;
        if (gaudit_run_parse_line(l, &ev) != 0) {
            fprintf(stderr, "not a run event: %s\n", l);
            failures++;
        }
    }
    CHECK(lines > 0);
    free(copy);
}

static char *run(const gaudit_selfcheck_env *env)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    gaudit_selfcheck(env, out);
    fclose(out);
    all_parse(buf);
    return buf;
}

/* A child running argv[0] with envp, stopped at once, so its /proc stays. */
static pid_t start(char *const argv[], char *const envp[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execve(argv[0], argv, envp);
        _exit(127);
    }
    usleep(200 * 1000);
    return pid;
}

static void stop(pid_t pid)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

int main(void)
{
    if (sodium_init() < 0 || mkdtemp(dir) == NULL)
        return 1;
    char own[256], a[300], b[300], extra[300], manifest[300], sigf[300], state[300];
    snprintf(own, sizeof own, "%s/own", dir);
    mkdir(own, 0755);
    snprintf(a, sizeof a, "%s/a", own);
    snprintf(b, sizeof b, "%s/b", own);
    snprintf(extra, sizeof extra, "%s/planted", own);
    snprintf(manifest, sizeof manifest, "%s/manifest", dir);
    snprintf(sigf, sizeof sigf, "%s/manifest.minisig", dir);
    snprintf(state, sizeof state, "%s/version", dir);
    put(a, "hello");
    put(b, "hello");
    const char *hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    char text[2048];
    snprintf(text, sizeof text,
             "gaudit-manifest 1\nversion 5\nsigned 1790000000\nexpires 1900000000\n"
             "file %s 5 %s\nfile %s 5 %s\n", hello, a, hello, b);
    put(manifest, text);
    unsigned char pk[32], sk[64], id[8];
    memset(id, 0x42, sizeof id);
    crypto_sign_keypair(pk, sk);
    char sig[1024];
    sign(sk, id, text, sig, sizeof sig);
    put(sigf, sig);
    gaudit_manifest_key key;
    memcpy(key.id, id, 8);
    memcpy(key.pk, pk, 32);
    const char *dirs[] = { own };
    const char *code[] = { "/usr/", "/lib" };
    gaudit_selfcheck_env env = {
        .manifest_path = manifest, .sig_path = sigf, .keys = &key, .n_keys = 1, .min_version = 1,
        .state_file = state, .dirs = dirs, .n_dirs = 1, .code_dirs = code, .n_code_dirs = 2,
        .now = 1795000000,
    };

    /* All as listed: fine, and the version kept. */
    char *out = run(&env);
    CHECK(strstr(out, "(self (manifest \"ok\") (version 5) (files 2) (changed 0) (missing 0) (extra 0)") != NULL);
    free(out);
    FILE *sf = fopen(state, "r");
    unsigned long long kept = 0;
    CHECK(sf != NULL && fscanf(sf, "%llu", &kept) == 1 && kept == 5);
    if (sf != NULL)
        fclose(sf);
    /* One changed, one gone, one planted. */
    put(a, "hellO");
    unlink(b);
    put(extra, "x");
    out = run(&env);
    CHECK(strstr(out, "(changed 1) (missing 1) (extra 1)") != NULL);
    CHECK(strstr(out, "(problem \"changed\")") != NULL && strstr(out, "(problem \"missing\")") != NULL
          && strstr(out, "planted\") (problem \"extra\")") != NULL);
    free(out);
    /* An older manifest than the one seen: refused. */
    env.min_version = 1;
    put(state, "6\n");
    out = run(&env);
    CHECK(strstr(out, "(manifest \"too-old\")") != NULL);
    free(out);
    /* No key built in, or no manifest. */
    env.n_keys = 0;
    out = run(&env);
    CHECK(strstr(out, "(manifest \"no-key\")") != NULL);
    free(out);
    env.n_keys = 1;
    unlink(manifest);
    out = run(&env);
    CHECK(strstr(out, "(manifest \"missing\")") != NULL);
    free(out);

    /* Processes: a system program started with GTK_MODULES ... */
    char *argv_sleep[] = { (char *)"/usr/bin/sleep", (char *)"30", NULL };
    char *envp[] = { (char *)"GTK_MODULES=evil", (char *)"HOME=/nowhere", NULL };
    pid_t p1 = start(argv_sleep, envp);
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    int problems = gaudit_selfcheck_process(&env, p1, "gui", "/usr/bin/sleep", mem);
    fclose(mem);
    CHECK(problems == 1 && strstr(buf, "(problem \"env\") (detail \"GTK_MODULES\")") != NULL);
    all_parse(buf);
    free(buf);
    stop(p1);
    /* ... and a copy of it from a folder the user owns: not the program it
     * should be, and code from outside the system's folders. */
    char copy[300], cmd[700];
    snprintf(copy, sizeof copy, "%s/sleep", dir);
    snprintf(cmd, sizeof cmd, "cp /usr/bin/sleep %s", copy);
    if (system(cmd) == 0) {
        char *argv_copy[] = { copy, (char *)"30", NULL };
        char *clean[] = { (char *)"HOME=/nowhere", NULL };
        pid_t p2 = start(argv_copy, clean);
        buf = NULL;
        mem = open_memstream(&buf, &len);
        problems = gaudit_selfcheck_process(&env, p2, "orchestrator", "/usr/bin/sleep", mem);
        fclose(mem);
        CHECK(problems == 2 && strstr(buf, "(problem \"exe\")") != NULL
              && strstr(buf, "(problem \"maps\")") != NULL);
        free(buf);
        stop(p2);
        unlink(copy);
    }

    unlink(a);
    unlink(extra);
    unlink(sigf);
    unlink(state);
    rmdir(own);
    rmdir(dir);
    if (failures == 0)
        puts("selfcheck: all checks passed");
    return failures == 0 ? 0 : 1;
}
