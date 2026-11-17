/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/run.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE  1024
#define MAX_COUNT 100000000LL

gaudit_verdict gaudit_firewall_verdict(const gaudit_firewall_report *r)
{
    if (r == NULL)
        return GAUDIT_VERDICT_UNKNOWN;
    if (r->input_chains > 0 && (r->input_drop > 0 || r->input_rules > 0))
        return GAUDIT_VERDICT_OK;
    if (r->legacy > 0)
        return GAUDIT_VERDICT_UNKNOWN;
    return GAUDIT_VERDICT_WARNING;
}

int gaudit_conf_result_known(const char *result)
{
    static const char *const names[] = {
        "written", "unchanged", "removed", "not-there", "foreign",
        "edited", "precondition", "unsafe", "error",
    };
    for (size_t i = 0; result != NULL && i < sizeof names / sizeof names[0]; i++)
        if (strcmp(result, names[i]) == 0)
            return 1;
    return 0;
}

int gaudit_vendor_result_known(const char *result)
{
    static const char *const names[] = {
        "verified", "weak", "installed", "no-file", "too-large", "not-signed", "unknown-key",
        "bad-signature", "weak-md5", "mismatch", "wrong-package", "not-newer", "not-verified",
        "failed", "error",
    };
    for (size_t i = 0; result != NULL && i < sizeof names / sizeof names[0]; i++)
        if (strcmp(result, names[i]) == 0)
            return 1;
    return 0;
}

/* A template id or action: [a-z0-9._-], not empty. */
static int plain_word(const char *s)
{
    if (s == NULL || *s == '\0')
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '_' || *c == '-'))
            return 0;
    return 1;
}

static int conf_valid(const gaudit_conf_report *c)
{
    return plain_word(c->template_id)
        && (strcmp(c->action, "on") == 0 || strcmp(c->action, "remove") == 0)
        && gaudit_conf_result_known(c->result);
}

/* A version or a hash name: [A-Za-z0-9.+~:-], may be empty. */
static int plain_version(const char *s)
{
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9')
              || *c == '.' || *c == '+' || *c == '~' || *c == ':' || *c == '-'))
            return 0;
    return 1;
}

static int vendor_valid(const gaudit_vendor_report *v)
{
    return plain_word(v->id)
        && (strcmp(v->action, "verify") == 0 || strcmp(v->action, "install") == 0)
        && gaudit_vendor_result_known(v->result) && plain_version(v->version)
        && plain_version(v->hash);
}

int gaudit_self_manifest_known(const char *name)
{
    static const char *const names[] = {
        "ok", "bad-signature", "bad-format", "expired", "too-old", "from-future", "missing", "no-key",
    };
    for (size_t i = 0; name != NULL && i < sizeof names / sizeof names[0]; i++)
        if (strcmp(name, names[i]) == 0)
            return 1;
    return 0;
}

gaudit_verdict gaudit_self_verdict(const gaudit_self_report *r)
{
    if (r == NULL)
        return GAUDIT_VERDICT_UNKNOWN;
    if (r->process_problems > 0 || r->changed > 0 || r->missing > 0 || r->extra > 0)
        return GAUDIT_VERDICT_WARNING;
    if (strcmp(r->manifest, "ok") == 0)
        return GAUDIT_VERDICT_OK;
    if (strcmp(r->manifest, "missing") == 0 || strcmp(r->manifest, "no-key") == 0)
        return GAUDIT_VERDICT_UNKNOWN;
    return GAUDIT_VERDICT_WARNING;
}

static int one_of(const char *s, const char *const *names, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(s, names[i]) == 0)
            return 1;
    return 0;
}

/* Printable ASCII without a quote or a backslash, as the helper writes it. */
static int plain_text(const char *s)
{
    for (const char *c = s; *c != '\0'; c++)
        if (*c < 0x20 || *c >= 0x7f || *c == '"' || *c == '\\')
            return 0;
    return 1;
}

static int self_file_valid(const gaudit_self_file *f)
{
    static const char *const problems[] = { "changed", "missing", "extra" };
    return f->path[0] == '/' && plain_text(f->path) && one_of(f->problem, problems, 3);
}

static int self_process_valid(const gaudit_self_process *p)
{
    static const char *const which[] = { "orchestrator", "gui" };
    static const char *const problems[] = { "exe", "env", "maps", "gone" };
    return one_of(p->which, which, 2) && one_of(p->problem, problems, 4) && plain_text(p->detail);
}

static int self_valid(const gaudit_self_report *r)
{
    return gaudit_self_manifest_known(r->manifest)
        && r->files_shown <= GAUDIT_SELF_SHOWN && r->processes_shown <= GAUDIT_SELF_SHOWN
        && r->files_shown <= r->changed + r->missing + r->extra
        && r->changed + r->missing <= r->files
        && r->processes_shown <= r->process_problems && r->processes <= 2
        && (strcmp(r->manifest, "ok") == 0 || (r->files == 0 && r->changed == 0
                                                && r->missing == 0 && r->extra == 0));
}

gaudit_verdict gaudit_integrity_verdict(const gaudit_integrity_report *r)
{
    if (r == NULL)
        return GAUDIT_VERDICT_UNKNOWN;
    if (r->changed > 0 || r->missing > 0)
        return GAUDIT_VERDICT_WARNING;
    if (r->unreadable > 0 || r->bad_lines > 0 || r->checked == 0)
        return GAUDIT_VERDICT_UNKNOWN;
    return GAUDIT_VERDICT_OK;
}

/* The report's own consistency, for the parser and the orchestrator. */
static int integrity_consistent(const gaudit_integrity_report *r)
{
    return r->checked <= r->files && r->changed <= r->checked
        && r->missing + r->unreadable + r->excluded + r->diverted + r->checked <= r->files
        && r->shown <= GAUDIT_INTEGRITY_SHOWN
        && r->shown <= r->changed + r->missing + r->unreadable;
}

int gaudit_run_format(const gaudit_run_event *ev, char *buf, size_t len)
{
    if (ev == NULL || buf == NULL)
        return -1;
    int n;
    const gaudit_firewall_report *f = &ev->firewall;
    switch (ev->type) {
    case GAUDIT_RUN_EVENT_ELEVATED:
        n = snprintf(buf, len, "(elevated (on %d))\n", ev->elevated ? 1 : 0);
        break;
    case GAUDIT_RUN_EVENT_FIREWALL:
        n = snprintf(buf, len,
                     "(firewall (verdict %d) (tables %u) (input-chains %u) (input-drop %u)"
                     " (input-rules %u) (rules %u) (legacy %u) (listening %u))\n",
                     (int)f->verdict, f->tables, f->input_chains, f->input_drop,
                     f->input_rules, f->rules, f->legacy, f->listening);
        break;
    case GAUDIT_RUN_EVENT_INTEGRITY_FILE: {
        char pkg[300], path[600];
        if (gaudit_probe_quote(pkg, sizeof pkg, ev->file.package) != 0
            || gaudit_probe_quote(path, sizeof path, ev->file.path) != 0)
            return -1;
        n = snprintf(buf, len, "(integrity-file (kind %d) (package %s) (path %s))\n",
                     (int)ev->file.kind, pkg, path);
        break;
    }
    case GAUDIT_RUN_EVENT_INTEGRITY: {
        const gaudit_integrity_report *r = &ev->integrity;
        n = snprintf(buf, len,
                     "(integrity (verdict %d) (packages %lu) (files %lu) (checked %lu) (changed %lu)"
                     " (missing %lu) (unreadable %lu) (excluded %lu) (diverted %lu) (bad-lines %lu)"
                     " (megabytes %lu) (shown %u) (seconds %u))\n",
                     (int)r->verdict, r->packages, r->files, r->checked, r->changed, r->missing,
                     r->unreadable, r->excluded, r->diverted, r->bad_lines, r->megabytes, r->shown,
                     r->seconds);
        break;
    }
    case GAUDIT_RUN_EVENT_CONF:
        if (!conf_valid(&ev->conf))
            return -1;
        n = snprintf(buf, len, "(conf (template \"%s\") (action \"%s\") (result \"%s\"))\n",
                     ev->conf.template_id, ev->conf.action, ev->conf.result);
        break;
    case GAUDIT_RUN_EVENT_EXEC:
        if (!plain_word(ev->exec.op) || ev->exec.status < 0 || ev->exec.status > 255)
            return -1;
        n = snprintf(buf, len, "(exec (op \"%s\") (status %d))\n", ev->exec.op, ev->exec.status);
        break;
    case GAUDIT_RUN_EVENT_VENDOR:
        if (!vendor_valid(&ev->vendor))
            return -1;
        n = snprintf(buf, len,
                     "(vendor (id \"%s\") (action \"%s\") (result \"%s\") (version \"%s\") (hash \"%s\"))\n",
                     ev->vendor.id, ev->vendor.action, ev->vendor.result, ev->vendor.version,
                     ev->vendor.hash);
        break;
    case GAUDIT_RUN_EVENT_SELF_FILE:
        if (!self_file_valid(&ev->self_file))
            return -1;
        n = snprintf(buf, len, "(self-file (path \"%s\") (problem \"%s\"))\n",
                     ev->self_file.path, ev->self_file.problem);
        break;
    case GAUDIT_RUN_EVENT_SELF_PROCESS:
        if (!self_process_valid(&ev->self_process))
            return -1;
        n = snprintf(buf, len, "(self-process (which \"%s\") (problem \"%s\") (detail \"%s\"))\n",
                     ev->self_process.which, ev->self_process.problem, ev->self_process.detail);
        break;
    case GAUDIT_RUN_EVENT_SELF: {
        const gaudit_self_report *r = &ev->self;
        if (!self_valid(r))
            return -1;
        n = snprintf(buf, len,
                     "(self (manifest \"%s\") (version %llu) (files %u) (changed %u) (missing %u)"
                     " (extra %u) (files-shown %u) (processes %u) (process-problems %u)"
                     " (processes-shown %u))\n",
                     r->manifest, r->version, r->files, r->changed, r->missing, r->extra,
                     r->files_shown, r->processes, r->process_problems, r->processes_shown);
        break;
    }
    case GAUDIT_RUN_EVENT_END:
        n = snprintf(buf, len, "(end (status %d))\n", (int)ev->status);
        break;
    default:
        return -1;
    }
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_run_parse_line(const char *line, gaudit_run_event *out)
{
    if (line == NULL || out == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';

    gaudit_run_event ev;
    memset(&ev, 0, sizeof ev);
    long long a, b, c, d, e, f, g, h;

    const gaudit_sexpr_field elevated[] = { { .key = "on", .value = &a, .max = 1 } };
    if (gaudit_sexpr_parse(copy, "elevated", elevated, 1) == 0) {
        ev.type = GAUDIT_RUN_EVENT_ELEVATED;
        ev.elevated = (int)a;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field end[] = { { .key = "status", .value = &a, .max = GAUDIT_RUN_FAILED } };
    if (gaudit_sexpr_parse(copy, "end", end, 1) == 0) {
        ev.type = GAUDIT_RUN_EVENT_END;
        ev.status = (gaudit_run_status)a;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field fw[] = {
        { .key = "verdict",      .value = &a, .max = GAUDIT_VERDICT_CRITICAL },
        { .key = "tables",       .value = &b, .max = MAX_COUNT },
        { .key = "input-chains", .value = &c, .max = MAX_COUNT },
        { .key = "input-drop",   .value = &d, .max = MAX_COUNT },
        { .key = "input-rules",  .value = &e, .max = MAX_COUNT },
        { .key = "rules",        .value = &f, .max = MAX_COUNT },
        { .key = "legacy",       .value = &g, .max = MAX_COUNT },
        { .key = "listening",    .value = &h, .max = 65536 },
    };
    long long k;
    const gaudit_sexpr_field file[] = {
        { .key = "kind",    .value = &k, .max = GAUDIT_INTEGRITY_FILE_UNREADABLE },
        { .key = "package", .text = ev.file.package, .text_len = sizeof ev.file.package },
        { .key = "path",    .text = ev.file.path, .text_len = sizeof ev.file.path },
    };
    if (gaudit_sexpr_parse(copy, "integrity-file", file, 3) == 0) {
        if (ev.file.package[0] == '\0' || ev.file.path[0] != '/')
            return -1;
        ev.type = GAUDIT_RUN_EVENT_INTEGRITY_FILE;
        ev.file.kind = (gaudit_integrity_file_kind)k;
        *out = ev;
        return 0;
    }
    long long v[13];
    static const char *const keys[13] = {
        "verdict", "packages", "files", "checked", "changed", "missing", "unreadable",
        "excluded", "diverted", "bad-lines", "megabytes", "shown", "seconds",
    };
    gaudit_sexpr_field integ[13];
    for (int i = 0; i < 13; i++)
        integ[i] = (gaudit_sexpr_field){ .key = keys[i], .value = &v[i], .max = MAX_COUNT };
    integ[0].max = GAUDIT_VERDICT_CRITICAL;
    if (gaudit_sexpr_parse(copy, "integrity", integ, 13) == 0) {
        gaudit_integrity_report *r = &ev.integrity;
        *r = (gaudit_integrity_report){
            .verdict = (gaudit_verdict)v[0], .packages = (unsigned long)v[1],
            .files = (unsigned long)v[2], .checked = (unsigned long)v[3],
            .changed = (unsigned long)v[4], .missing = (unsigned long)v[5],
            .unreadable = (unsigned long)v[6], .excluded = (unsigned long)v[7],
            .diverted = (unsigned long)v[8], .bad_lines = (unsigned long)v[9],
            .megabytes = (unsigned long)v[10], .shown = (unsigned)v[11], .seconds = (unsigned)v[12],
        };
        if (!integrity_consistent(r) || r->verdict != gaudit_integrity_verdict(r))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_INTEGRITY;
        *out = ev;
        return 0;
    }
    long long xs;
    const gaudit_sexpr_field exec[] = {
        { .key = "op",     .text = ev.exec.op, .text_len = sizeof ev.exec.op },
        { .key = "status", .value = &xs, .max = 255 },
    };
    if (gaudit_sexpr_parse(copy, "exec", exec, 2) == 0) {
        if (!plain_word(ev.exec.op))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_EXEC;
        ev.exec.status = (int)xs;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field conf[] = {
        { .key = "template", .text = ev.conf.template_id, .text_len = sizeof ev.conf.template_id },
        { .key = "action",   .text = ev.conf.action,      .text_len = sizeof ev.conf.action },
        { .key = "result",   .text = ev.conf.result,      .text_len = sizeof ev.conf.result },
    };
    const gaudit_sexpr_field vendor[] = {
        { .key = "id",      .text = ev.vendor.id,      .text_len = sizeof ev.vendor.id },
        { .key = "action",  .text = ev.vendor.action,  .text_len = sizeof ev.vendor.action },
        { .key = "result",  .text = ev.vendor.result,  .text_len = sizeof ev.vendor.result },
        { .key = "version", .text = ev.vendor.version, .text_len = sizeof ev.vendor.version },
        { .key = "hash",    .text = ev.vendor.hash,    .text_len = sizeof ev.vendor.hash },
    };
    if (gaudit_sexpr_parse(copy, "vendor", vendor, 5) == 0) {
        if (!vendor_valid(&ev.vendor))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_VENDOR;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field self_file[] = {
        { .key = "path",    .text = ev.self_file.path,    .text_len = sizeof ev.self_file.path },
        { .key = "problem", .text = ev.self_file.problem, .text_len = sizeof ev.self_file.problem },
    };
    if (gaudit_sexpr_parse(copy, "self-file", self_file, 2) == 0) {
        if (!self_file_valid(&ev.self_file))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_SELF_FILE;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field self_process[] = {
        { .key = "which",   .text = ev.self_process.which,   .text_len = sizeof ev.self_process.which },
        { .key = "problem", .text = ev.self_process.problem, .text_len = sizeof ev.self_process.problem },
        { .key = "detail",  .text = ev.self_process.detail,  .text_len = sizeof ev.self_process.detail },
    };
    if (gaudit_sexpr_parse(copy, "self-process", self_process, 3) == 0) {
        if (!self_process_valid(&ev.self_process))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_SELF_PROCESS;
        *out = ev;
        return 0;
    }
    long long sv[9];
    static const char *const self_keys[9] = {
        "version", "files", "changed", "missing", "extra", "files-shown", "processes",
        "process-problems", "processes-shown",
    };
    gaudit_sexpr_field self[10];
    self[0] = (gaudit_sexpr_field){ .key = "manifest", .text = ev.self.manifest,
                                    .text_len = sizeof ev.self.manifest };
    for (int i = 0; i < 9; i++)
        self[i + 1] = (gaudit_sexpr_field){ .key = self_keys[i], .value = &sv[i], .max = MAX_COUNT };
    self[1].max = 999999999999999999LL;  /* a version: at most 18 digits (manifest.h) */
    if (gaudit_sexpr_parse(copy, "self", self, 10) == 0) {
        gaudit_self_report *r = &ev.self;
        r->version = (unsigned long long)sv[0];
        r->files = (unsigned)sv[1];
        r->changed = (unsigned)sv[2];
        r->missing = (unsigned)sv[3];
        r->extra = (unsigned)sv[4];
        r->files_shown = (unsigned)sv[5];
        r->processes = (unsigned)sv[6];
        r->process_problems = (unsigned)sv[7];
        r->processes_shown = (unsigned)sv[8];
        if (!self_valid(r))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_SELF;
        *out = ev;
        return 0;
    }
    if (gaudit_sexpr_parse(copy, "conf", conf, 3) == 0) {
        if (!conf_valid(&ev.conf))
            return -1;
        ev.type = GAUDIT_RUN_EVENT_CONF;
        *out = ev;
        return 0;
    }
    if (gaudit_sexpr_parse(copy, "firewall", fw, sizeof fw / sizeof fw[0]) == 0) {
        ev.type = GAUDIT_RUN_EVENT_FIREWALL;
        ev.firewall = (gaudit_firewall_report){
            .verdict = (gaudit_verdict)a, .tables = (unsigned)b, .input_chains = (unsigned)c,
            .input_drop = (unsigned)d, .input_rules = (unsigned)e, .rules = (unsigned)f,
            .legacy = (unsigned)g, .listening = (unsigned)h,
        };
        *out = ev;
        return 0;
    }
    return -1;
}
