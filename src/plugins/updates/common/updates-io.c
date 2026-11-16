/* SPDX-License-Identifier: GPL-3.0-only */
#include "updates.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 1024  /* a vendor-package line, quoted in full */

static const char *const key_names[GAUDIT_UPDATE_KEYS] = {
    [GAUDIT_UPDATE_BACKEND]            = "backend",
    [GAUDIT_UPDATE_EXPECTED_MISSING]   = "expected-missing",
    [GAUDIT_UPDATE_OTHER_SYSTEMS]      = "other-systems",
    [GAUDIT_UPDATE_CHECK_DAYS]         = "check-days",
    [GAUDIT_UPDATE_INSTALL]            = "install",
    [GAUDIT_UPDATE_DOWNLOAD]           = "download",
    [GAUDIT_UPDATE_CHECK_TIMER]        = "check-timer",
    [GAUDIT_UPDATE_INSTALL_TIMER]      = "install-timer",
    [GAUDIT_UPDATE_LAST_INSTALL]       = "last-install",
    [GAUDIT_UPDATE_LAST_CHANGE]        = "last-change",
    [GAUDIT_UPDATE_ADMIN_TOOLS]        = "admin-tools",
    [GAUDIT_UPDATE_OWN_SETTING]        = "own-setting",
    [GAUDIT_UPDATE_UPGRADE_UPDATES]    = "upgrade-updates",
    [GAUDIT_UPDATE_UNREAD_SOURCES]     = "unread-sources",
    [GAUDIT_UPDATE_UPGRADE_OFF]        = "upgrade-off",
    [GAUDIT_UPDATE_INDEX_AGE]          = "index-age",
    [GAUDIT_UPDATE_PENDING]            = "pending",
    [GAUDIT_UPDATE_PENDING_SECURITY]   = "pending-security",
    [GAUDIT_UPDATE_SECURITY_OFFICIAL]  = "security-official",
    [GAUDIT_UPDATE_SECURITY_MIRROR]    = "security-mirror",
    [GAUDIT_UPDATE_SOURCELESS]         = "sourceless",
    [GAUDIT_UPDATE_SOURCELESS_ABOVE]   = "sourceless-above",
    [GAUDIT_UPDATE_SOURCELESS_LEFTOVER] = "sourceless-leftover",
    [GAUDIT_UPDATE_SOURCELESS_OTHER]   = "sourceless-other",
    [GAUDIT_UPDATE_SOURCELESS_VENDOR]  = "sourceless-vendor",
    [GAUDIT_UPDATE_SOURCELESS_KEPT]    = "sourceless-kept",
};

const char *gaudit_update_key_name(gaudit_update_key key)
{
    return key >= 0 && key < GAUDIT_UPDATE_KEYS ? key_names[key] : NULL;
}

/* Values fit comfortably: ages in seconds, counts, days. */
#define VALUE_MIN -1LL
#define VALUE_MAX 100000000000LL

int gaudit_update_format_fact(const gaudit_update_fact *f, char *buf, size_t len)
{
    char text[sizeof f->text * 2 + 3];
    if (f == NULL || buf == NULL || gaudit_update_key_name(f->key) == NULL
        || f->status < GAUDIT_FACT_KNOWN || f->status > GAUDIT_FACT_NOT_APPLICABLE
        || f->value < VALUE_MIN || f->value > VALUE_MAX
        || gaudit_probe_quote(text, sizeof text, f->text) != 0)
        return -1;
    int n = snprintf(buf, len, "(fact (key \"%s\") (status %d) (value %lld) (text %s))\n",
                     key_names[f->key], (int)f->status, f->value, text);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_format_end(unsigned count, char *buf, size_t len)
{
    int n = snprintf(buf, len, "(facts (count %u))\n", count);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_line(const char *line, gaudit_update_fact *fact, unsigned *count)
{
    if (line == NULL || fact == NULL || count == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';

    if (strncmp(copy, "(facts ", 7) == 0) {
        long long n;
        const gaudit_sexpr_field fields[] = {
            { .key = "count", .value = &n, .max = GAUDIT_UPDATE_KEYS },
        };
        if (gaudit_sexpr_parse(copy, "facts", fields, 1) != 0)
            return -1;
        *count = (unsigned)n;
        return 2;
    }

    char key[32];
    gaudit_update_fact f;
    memset(&f, 0, sizeof f);
    long long status;
    const gaudit_sexpr_field fields[] = {
        { .key = "key",    .text = key,     .text_len = sizeof key },
        { .key = "status", .value = &status, .max = GAUDIT_FACT_NOT_APPLICABLE },
        { .key = "value",  .value = &f.value, .min = VALUE_MIN, .max = VALUE_MAX },
        { .key = "text",   .text = f.text,  .text_len = sizeof f.text },
    };
    if (gaudit_sexpr_parse(copy, "fact", fields, sizeof fields / sizeof fields[0]) != 0)
        return -1;
    for (int k = 0; k < GAUDIT_UPDATE_KEYS; k++) {
        if (strcmp(key, key_names[k]) == 0) {
            f.key = (gaudit_update_key)k;
            f.status = (gaudit_fact_status)status;
            *fact = f;
            return 1;
        }
    }
    return -1;
}

int gaudit_update_format_vendor(const gaudit_update_vendor *v, char *buf, size_t len)
{
    char id[sizeof v->id * 2 + 3], title[sizeof v->title * 2 + 3], vendor[sizeof v->vendor * 2 + 3],
         version[sizeof v->version * 2 + 3];
    if (v == NULL || buf == NULL || v->id[0] == '\0'
        || gaudit_probe_quote(id, sizeof id, v->id) != 0
        || gaudit_probe_quote(title, sizeof title, v->title) != 0
        || gaudit_probe_quote(vendor, sizeof vendor, v->vendor) != 0
        || gaudit_probe_quote(version, sizeof version, v->version) != 0)
        return -1;
    int n = snprintf(buf, len, "(vendor-package (id %s) (title %s) (vendor %s) (version %s))\n",
                     id, title, vendor, version);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_vendor(const char *line, gaudit_update_vendor *v)
{
    if (line == NULL || v == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';
    gaudit_update_vendor out;
    memset(&out, 0, sizeof out);
    const gaudit_sexpr_field fields[] = {
        { .key = "id",      .text = out.id,      .text_len = sizeof out.id },
        { .key = "title",   .text = out.title,   .text_len = sizeof out.title },
        { .key = "vendor",  .text = out.vendor,  .text_len = sizeof out.vendor },
        { .key = "version", .text = out.version, .text_len = sizeof out.version },
    };
    if (gaudit_sexpr_parse(copy, "vendor-package", fields, sizeof fields / sizeof fields[0]) != 0
        || out.id[0] == '\0')
        return -1;
    *v = out;
    return 0;
}

int gaudit_update_format_latest(const gaudit_update_latest *l, char *buf, size_t len)
{
    char id[sizeof l->id * 2 + 3], version[sizeof l->version * 2 + 3],
         installed[sizeof l->installed * 2 + 3];
    if (l == NULL || buf == NULL || l->id[0] == '\0' || l->status < 0 || l->status > 1
        || l->newer < 0 || l->newer > 1
        || gaudit_probe_quote(id, sizeof id, l->id) != 0
        || gaudit_probe_quote(version, sizeof version, l->version) != 0
        || gaudit_probe_quote(installed, sizeof installed, l->installed) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(vendor-latest (id %s) (status %d) (version %s) (installed %s) (newer %d))\n",
                     id, l->status, version, installed, l->newer);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_latest(const char *line, gaudit_update_latest *l)
{
    if (line == NULL || l == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';
    gaudit_update_latest out;
    memset(&out, 0, sizeof out);
    long long status, newer;
    const gaudit_sexpr_field fields[] = {
        { .key = "id",        .text = out.id,        .text_len = sizeof out.id },
        { .key = "status",    .value = &status,      .max = 1 },
        { .key = "version",   .text = out.version,   .text_len = sizeof out.version },
        { .key = "installed", .text = out.installed, .text_len = sizeof out.installed },
        { .key = "newer",     .value = &newer,       .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "vendor-latest", fields, sizeof fields / sizeof fields[0]) != 0
        || out.id[0] == '\0' || (status == 1 && newer != 0))
        return -1;
    out.status = (int)status;
    out.newer = (int)newer;
    *l = out;
    return 0;
}

int gaudit_update_format_download(const gaudit_update_download *d, char *buf, size_t len)
{
    static char path[sizeof d->path * 2 + 3];
    char id[sizeof d->id * 2 + 3], reason[sizeof d->reason * 2 + 3];
    if (d == NULL || buf == NULL || d->id[0] == '\0' || d->status < 0 || d->status > 1
        || gaudit_probe_quote(reason, sizeof reason, d->reason) != 0
        || (d->status == 0) != (d->path[0] != '\0')
        || gaudit_probe_quote(id, sizeof id, d->id) != 0
        || gaudit_probe_quote(path, sizeof path, d->path) != 0)
        return -1;
    int n = snprintf(buf, len, "(vendor-download (id %s) (status %d) (path %s) (reason %s))\n", id,
                     d->status, path, reason);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_download(const char *line, gaudit_update_download *d)
{
    if (line == NULL || d == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= 8192 || memchr(line, '\n', len) != NULL)
        return -1;
    static char copy[8192];
    memcpy(copy, line, len);
    copy[len] = '\0';
    static gaudit_update_download out;
    memset(&out, 0, sizeof out);
    long long status;
    const gaudit_sexpr_field fields[] = {
        { .key = "id",     .text = out.id,   .text_len = sizeof out.id },
        { .key = "status", .value = &status, .max = 1 },
        { .key = "path",   .text = out.path, .text_len = sizeof out.path },
        { .key = "reason", .text = out.reason, .text_len = sizeof out.reason },
    };
    if (gaudit_sexpr_parse(copy, "vendor-download", fields, 4) != 0 || out.id[0] == '\0'
        || (status == 0) != (out.path[0] != '\0'))
        return -1;
    out.status = (int)status;
    *d = out;
    return 0;
}

int gaudit_update_format_local(const gaudit_update_local *l, char *buf, size_t len)
{
    char q[9][140];
    const char *src[9] = { l != NULL ? l->id : NULL };
    if (l == NULL || buf == NULL || l->id[0] == '\0')
        return -1;
    src[1] = l->title;
    src[2] = l->vendor;
    src[3] = l->version;
    src[4] = l->made_for;
    src[5] = l->made_for_name;
    src[6] = l->running;
    src[7] = l->previous;
    for (int i = 0; i < 8; i++)
        if (gaudit_probe_quote(q[i], sizeof q[i], src[i]) != 0)
            return -1;
    int n = snprintf(buf, len,
                     "(vendor-local (id %s) (title %s) (vendor %s) (version %s) (made-for %s)"
                     " (made-for-name %s) (running %s) (previous %s) (packages %u))\n",
                     q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], l->packages);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_local(const char *line, gaudit_update_local *l)
{
    if (line == NULL || l == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';
    gaudit_update_local out;
    memset(&out, 0, sizeof out);
    long long packages;
    const gaudit_sexpr_field fields[] = {
        { .key = "id",            .text = out.id,            .text_len = sizeof out.id },
        { .key = "title",         .text = out.title,         .text_len = sizeof out.title },
        { .key = "vendor",        .text = out.vendor,        .text_len = sizeof out.vendor },
        { .key = "version",       .text = out.version,       .text_len = sizeof out.version },
        { .key = "made-for",      .text = out.made_for,      .text_len = sizeof out.made_for },
        { .key = "made-for-name", .text = out.made_for_name, .text_len = sizeof out.made_for_name },
        { .key = "running",       .text = out.running,       .text_len = sizeof out.running },
        { .key = "previous",      .text = out.previous,      .text_len = sizeof out.previous },
        { .key = "packages",      .value = &packages,        .max = 100000 },
    };
    if (gaudit_sexpr_parse(copy, "vendor-local", fields, sizeof fields / sizeof fields[0]) != 0
        || out.id[0] == '\0')
        return -1;
    out.packages = (unsigned)packages;
    *l = out;
    return 0;
}

int gaudit_update_format_companion(const gaudit_update_companion *c, char *buf, size_t len)
{
    char id[70], package[260], manager[132], version[196];
    if (c == NULL || buf == NULL || c->id[0] == '\0' || c->present < 0 || c->present > 1
        || gaudit_probe_quote(id, sizeof id, c->id) != 0
        || gaudit_probe_quote(package, sizeof package, c->package) != 0
        || gaudit_probe_quote(manager, sizeof manager, c->manager) != 0
        || gaudit_probe_quote(version, sizeof version, c->version) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(vendor-companion (id %s) (package %s) (manager %s) (version %s) (present %d))\n",
                     id, package, manager, version, c->present);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_update_parse_companion(const char *line, gaudit_update_companion *c)
{
    if (line == NULL || c == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';
    gaudit_update_companion out;
    memset(&out, 0, sizeof out);
    long long present;
    const gaudit_sexpr_field fields[] = {
        { .key = "id",      .text = out.id,      .text_len = sizeof out.id },
        { .key = "package", .text = out.package, .text_len = sizeof out.package },
        { .key = "manager", .text = out.manager, .text_len = sizeof out.manager },
        { .key = "version", .text = out.version, .text_len = sizeof out.version },
        { .key = "present", .value = &present,   .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "vendor-companion", fields, 5) != 0 || out.id[0] == '\0')
        return -1;
    out.present = (int)present;
    *c = out;
    return 0;
}
