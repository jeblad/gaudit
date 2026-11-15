/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates collection: its lines round-trip and refuse what they
 * should, and a collection from a made-up backend has every key exactly
 * once, the counts as the backend gave them, and a closing count that
 * matches. */
#include "updates.h"
#include "updates-mode.h"

#include <stdio.h>
#include <stdlib.h>
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

#define NOW 1700000000

static gaudit_backend_status settings(gaudit_update_settings *out)
{
    *out = (gaudit_update_settings){ .check_days = 0, .install = 1, .download = -1,
                                     .check_timer = 1, .install_timer = 0,
                                     .last_install = NOW - 3600, .last_change = NOW - 7200,
                                     .admin_tools = 1, .admin_names = "synaptic",
                                     .own_setting = 0, .upgrade_updates = 1 };
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status counts(unsigned *obsolete, unsigned *upgradable, unsigned *security)
{
    *obsolete = 3;
    *upgradable = 7;
    *security = 2;
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status sourceless(gaudit_sourceless_fn fn, void *ctx)
{
    fn("a", "amd64", "1", GAUDIT_SOURCELESS_ABOVE_SOURCE, "0.9", ctx);
    fn("b", "amd64", "1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    fn("c", "amd64", "1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status index_update(int64_t *epoch)
{
    *epoch = NOW + 10;  /* from the future: unknown */
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status sources(unsigned *official, unsigned *mirror, char *host, size_t len)
{
    *official = 1;
    *mirror = 1;
    snprintf(host, len, "%s", "mirror.example.org");
    return GAUDIT_BACKEND_OK;
}

static unsigned systems(void)
{
    return 1u << GAUDIT_PKGSYS_DPKG | 1u << GAUDIT_PKGSYS_RPM | 1u << GAUDIT_PKGSYS_NIX;
}

static const gaudit_pkg_backend fake = {
    .name = "fake", .package_system = "fake", .own_package_system = GAUDIT_PKGSYS_DPKG,
    .package_systems_present = systems, .update_settings = settings,
    .package_counts = counts, .sourceless_packages = sourceless,
    .last_index_update = index_update, .security_sources = sources,
};
static const gaudit_pkg_backend expected = { .name = "other", .package_system = "dpkg/apt" };
static const gaudit_pkg_backend bare = { .name = "bare" };

/* Collects from pkg; facts[] by key, seen[] how often each came. */
static int collect(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *exp,
                   gaudit_update_fact facts[GAUDIT_UPDATE_KEYS], int seen[GAUDIT_UPDATE_KEYS])
{
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    if (out == NULL || gaudit_updates_collect(pkg, exp, NOW, out) != 0) {
        if (out != NULL)
            fclose(out);
        free(buf);
        return -1;
    }
    fclose(out);
    memset(seen, 0, sizeof(int) * GAUDIT_UPDATE_KEYS);
    unsigned lines = 0, count = 0;
    int ended = 0, bad = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        gaudit_update_fact f;
        int kind = gaudit_update_parse_line(line, &f, &count);
        if (kind == 1 && !ended) {
            facts[f.key] = f;
            seen[f.key]++;
            lines++;
        } else if (kind == 2 && !ended) {
            ended = 1;
        } else {
            bad = 1;
        }
    }
    free(buf);
    return !bad && ended && count == lines ? 0 : -1;
}

int main(void)
{
    /* Lines round-trip. */
    gaudit_update_fact f = { .key = GAUDIT_UPDATE_SECURITY_MIRROR, .status = GAUDIT_FACT_KNOWN,
                             .value = 2 }, g;
    snprintf(f.text, sizeof f.text, "%s", "a \"quoted\" \\ host");
    char line[512];
    unsigned n = 99;
    CHECK(gaudit_update_format_fact(&f, line, sizeof line) == 0);
    CHECK(gaudit_update_parse_line(line, &g, &n) == 1 && g.key == f.key && g.status == f.status
          && g.value == 2 && strcmp(g.text, f.text) == 0);
    CHECK(gaudit_update_format_end(18, line, sizeof line) == 0);
    CHECK(gaudit_update_parse_line(line, &g, &n) == 2 && n == 18);
    f.value = -1;
    CHECK(gaudit_update_format_fact(&f, line, sizeof line) == 0);
    f.value = -2;  /* below what any fact holds */
    CHECK(gaudit_update_format_fact(&f, line, sizeof line) != 0);

    /* And refuse what they should. */
    const char *bad[] = {
        "(fact (key \"no-such-key\") (status 0) (value 0) (text \"\"))",
        "(fact (key \"pending\") (status 4) (value 0) (text \"\"))",
        "(fact (key \"pending\") (status 0) (value -2) (text \"\"))",
        "(fact (key \"pending\") (status 0) (value 0))",
        "(fact (key \"pending\") (status 0) (value 0) (text \"\") (text \"\"))",
        "(fact (key \"pending\") (status 0) (value 0) (text \"\")) extra",
        "(facts (count 99))",
        "(secret (area 0))",
        "",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(gaudit_update_parse_line(bad[i], &g, &n) == -1);

    /* Every key exactly once, as the backend gave it. */
    gaudit_update_fact facts[GAUDIT_UPDATE_KEYS];
    int seen[GAUDIT_UPDATE_KEYS];
    CHECK(collect(&fake, &expected, facts, seen) == 0);
    for (int k = 0; k < GAUDIT_UPDATE_KEYS; k++)
        CHECK(seen[k] == 1);
    CHECK(strcmp(facts[GAUDIT_UPDATE_BACKEND].text, "fake") == 0);
    CHECK(facts[GAUDIT_UPDATE_EXPECTED_MISSING].value == 1
          && strcmp(facts[GAUDIT_UPDATE_EXPECTED_MISSING].text, "dpkg/apt") == 0);
    CHECK(facts[GAUDIT_UPDATE_OTHER_SYSTEMS].value == 2
          && strcmp(facts[GAUDIT_UPDATE_OTHER_SYSTEMS].text, "rpm, Nix") == 0);
    CHECK(facts[GAUDIT_UPDATE_CHECK_DAYS].status == GAUDIT_FACT_KNOWN
          && facts[GAUDIT_UPDATE_CHECK_DAYS].value == 0);
    CHECK(facts[GAUDIT_UPDATE_DOWNLOAD].status == GAUDIT_FACT_UNKNOWN);
    CHECK(facts[GAUDIT_UPDATE_INSTALL_TIMER].value == 0);
    CHECK(facts[GAUDIT_UPDATE_LAST_INSTALL].value == 3600);
    CHECK(facts[GAUDIT_UPDATE_LAST_CHANGE].value == 7200);
    CHECK(facts[GAUDIT_UPDATE_ADMIN_TOOLS].value == 1
          && strcmp(facts[GAUDIT_UPDATE_ADMIN_TOOLS].text, "synaptic") == 0);
    CHECK(facts[GAUDIT_UPDATE_INDEX_AGE].status == GAUDIT_FACT_UNKNOWN);
    CHECK(facts[GAUDIT_UPDATE_PENDING].value == 7 && facts[GAUDIT_UPDATE_PENDING_SECURITY].value == 2);
    CHECK(facts[GAUDIT_UPDATE_SOURCELESS].value == 3
          && facts[GAUDIT_UPDATE_SOURCELESS_ABOVE].value == 1
          && facts[GAUDIT_UPDATE_SOURCELESS_LEFTOVER].value == 0
          && facts[GAUDIT_UPDATE_SOURCELESS_OTHER].value == 2);
    CHECK(facts[GAUDIT_UPDATE_SECURITY_MIRROR].value == 1
          && strcmp(facts[GAUDIT_UPDATE_SECURITY_MIRROR].text, "mirror.example.org") == 0);

    /* A backend that can do nothing: every key still there, none made up. */
    CHECK(collect(&bare, NULL, facts, seen) == 0);
    for (int k = 0; k < GAUDIT_UPDATE_KEYS; k++)
        CHECK(seen[k] == 1);
    CHECK(facts[GAUDIT_UPDATE_EXPECTED_MISSING].status == GAUDIT_FACT_NOT_APPLICABLE);
    CHECK(facts[GAUDIT_UPDATE_CHECK_DAYS].status == GAUDIT_FACT_UNSUPPORTED);
    CHECK(facts[GAUDIT_UPDATE_INSTALL].status == GAUDIT_FACT_UNSUPPORTED);
    CHECK(facts[GAUDIT_UPDATE_PENDING].status == GAUDIT_FACT_UNSUPPORTED);
    CHECK(facts[GAUDIT_UPDATE_PENDING_SECURITY].status == GAUDIT_FACT_UNSUPPORTED);
    CHECK(facts[GAUDIT_UPDATE_SECURITY_MIRROR].status == GAUDIT_FACT_NOT_APPLICABLE);

    if (failures == 0)
        puts("updates: all checks passed");
    return failures == 0 ? 0 : 1;
}
