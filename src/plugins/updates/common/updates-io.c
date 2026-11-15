/* SPDX-License-Identifier: GPL-3.0-only */
#include "updates.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 512

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
    [GAUDIT_UPDATE_INDEX_AGE]          = "index-age",
    [GAUDIT_UPDATE_PENDING]            = "pending",
    [GAUDIT_UPDATE_PENDING_SECURITY]   = "pending-security",
    [GAUDIT_UPDATE_SECURITY_OFFICIAL]  = "security-official",
    [GAUDIT_UPDATE_SECURITY_MIRROR]    = "security-mirror",
    [GAUDIT_UPDATE_SOURCELESS]         = "sourceless",
    [GAUDIT_UPDATE_SOURCELESS_ABOVE]   = "sourceless-above",
    [GAUDIT_UPDATE_SOURCELESS_LEFTOVER] = "sourceless-leftover",
    [GAUDIT_UPDATE_SOURCELESS_OTHER]   = "sourceless-other",
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
