/* SPDX-License-Identifier: GPL-3.0-only */
/* The deep scan's findings over the orchestrator pipe: write and read
 * back, and reject anything else (the verdict is the rule's, tested with
 * the engine). The GUI treats this input
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

static void test_area(void)
{
    gaudit_secret_area a = { .index = 2, .status = GAUDIT_AREA_SEARCHED, .remote = 1, .exact = 1 };
    snprintf(a.path, sizeof a.path, "/mnt/my \"data\"");
    char line[1024];
    CHECK(gaudit_secrets_format_area(&a, line, sizeof line) == 0);
    gaudit_secret_area b;
    gaudit_secret_finding f;
    gaudit_secrets_summary s;
    CHECK(gaudit_secrets_parse_area(line, &b) == 0);
    CHECK(b.index == 2 && strcmp(b.path, a.path) == 0 && b.remote == 1 && b.exact == 1);
    CHECK(gaudit_secrets_parse_line(line, &f, &s) == 3);
    static const char *const bad[] = {
        "(area (index 16) (path \"/x\") (status 0) (remote 0) (exact 1))",
        "(area (index 1) (path \"x\") (status 0) (remote 0) (exact 1))",
        "(area (index 1) (path \"/x\") (status 3) (remote 0) (exact 1))",
        "(area (index 1) (path \"/x\") (status 0) (exact 1))",
        "(secret (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (area 16) (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (gaudit_secrets_parse_area(bad[i], &b) == 0 || gaudit_secrets_parse_line(bad[i], &f, &s) > 0) {
            fprintf(stderr, "accepted: %s\n", bad[i]);
            failures++;
        }
}

static void test_reject(void)
{
    static const char *const bad[] = {
        "",
        "(secret (area 0) (path \"/etc/shadow\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (area 0) (path \"../other/key\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (area 0) (path \"a/../../key\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (area 0) (path \"k\") (reason \"\") (mode 384) (reach 0) (owned 1) (exact 1))",
        "(secret (area 0) (path \"k\") (reason \"x\") (mode 99999) (reach 0) (owned 1) (exact 1))",
        "(secret (area 0) (path \"k\") (reason \"x\") (mode 384) (reach 4) (owned 1) (exact 1))",
        "(secret (area 0) (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1))",
        "(secret (area 0) (path \"k\") (reason \"x\") (mode 384) (reach 0) (owned 1) (exact 1) (exact 1))",
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

int main(void)
{
    test_round_trip();
    test_area();
    test_reject();
    if (failures == 0)
        puts("secrets-io: all checks passed");
    return failures == 0 ? 0 : 1;
}
