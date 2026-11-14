/* SPDX-License-Identifier: GPL-3.0-only */
/* The deep scan's findings over the orchestrator pipe: write and read
 * back, reject anything else, and the verdict. The GUI treats this input
 * as untrusted. */
#include "secrets.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

static void test_round_trip(void)
{
    gaudit_secret_finding f = { .mode = 0644, .reach = GAUDIT_SECRET_OTHERS, .owned = 1, .exact = 1 };
    snprintf(f.path, sizeof f.path, "Desktop/my \"key\".pem");
    snprintf(f.reason, sizeof f.reason, "pem-private-key");
    char line[1024];
    CHECK(gaudit_secrets_format_finding(&f, line, sizeof line) == 0);
    gaudit_secret_finding g;
    gaudit_secrets_summary s;
    CHECK(gaudit_secrets_parse_line(line, &g, &s) == 1);
    CHECK(strcmp(g.path, f.path) == 0 && strcmp(g.reason, f.reason) == 0);
    CHECK(g.mode == 0644 && g.reach == GAUDIT_SECRET_OTHERS && g.owned == 1 && g.exact == 1);

    gaudit_secrets_summary sum = { .status = GAUDIT_SECRETS_OK, .count = 3, .shown = 3,
                                   .others = 1, .groups = 1 };
    CHECK(gaudit_secrets_format_summary(&sum, line, sizeof line) == 0);
    CHECK(gaudit_secrets_parse_line(line, &g, &s) == 2);
    CHECK(s.count == 3 && s.shown == 3 && s.others == 1 && s.groups == 1 && !s.truncated);
}

static void test_reject(void)
{
    static const char *const bad[] = {
        "",
        "(secret (path \"/etc/shadow\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (path \"../other/key\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (path \"a/../../key\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (path \"k\") (reason \"\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (path \"k\") (reason \"x\") (mode 99999) (reach 0) (owned 1) (exact 1))",
        "(secret (path \"k\") (reason \"x\") (mode 384) (reach 4) (owned 1) (exact 1))",
        "(secret (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1))",
        "(secret (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1) (exact 1))",
        "(secrets (status 0) (count 2) (shown 3) (others 0) (groups 0) (truncated 0))",
        "(secrets (status 0) (count 2) (shown 2) (others 2) (groups 1) (truncated 0))",
        "(secrets (status 2) (count 0) (shown 0) (others 0) (groups 0) (truncated 0))",
        "(packages (status 0) (count 0) (shown 0))",
    };
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (gaudit_secrets_parse_line(bad[i], &f, &s) != -1) {
            fprintf(stderr, "accepted: %s\n", bad[i]);
            failures++;
        }
}

static void test_verdict(void)
{
    gaudit_secrets_summary s = { .status = GAUDIT_SECRETS_OK, .count = 4 };
    CHECK(gaudit_secrets_verdict(&s) == GAUDIT_VERDICT_OK);       /* only the user's own */
    s.groups = 1;
    CHECK(gaudit_secrets_verdict(&s) == GAUDIT_VERDICT_WARNING);
    s.groups = 0;
    s.truncated = 1;
    CHECK(gaudit_secrets_verdict(&s) == GAUDIT_VERDICT_UNKNOWN);  /* the rest is not known */
    s.others = 1;
    CHECK(gaudit_secrets_verdict(&s) == GAUDIT_VERDICT_WARNING);  /* a found one still warns */
    s = (gaudit_secrets_summary){ .status = GAUDIT_SECRETS_UNKNOWN };
    CHECK(gaudit_secrets_verdict(&s) == GAUDIT_VERDICT_UNKNOWN);
}

int main(void)
{
    test_round_trip();
    test_reject();
    test_verdict();
    if (failures == 0)
        puts("secrets-io: all checks passed");
    return failures == 0 ? 0 : 1;
}
