/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates collection: its lines round-trip and refuse what they
 * should, and a collection from a made-up backend has every key exactly
 * once, the counts as the backend gave them, and a closing count that
 * matches; a known vendor package is taken out of the groups, by its name
 * and its maker together. */
#include "updates.h"
#include "updates-mode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

#define NOW 1700000000

static gaudit_backend_status settings(gaudit_update_settings *out)
{
    *out = (gaudit_update_settings){ .check_days = 0, .install = 1, .download = -1,
                                     .check_timer = 1, .install_timer = 0,
                                     .last_install = NOW - 3600, .last_change = NOW - 7200,
                                     .admin_tools = 1, .admin_names = "synaptic",
                                     .own_setting = 0, .upgrade_updates = 1,
                                     .unread_sources = 1, .unread_names = "prerelease.keybase.io",
                                     .upgrade_off = 1, .upgrade_off_names = "ppa:cappelikan/ppa" };
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status counts(unsigned *obsolete, unsigned *upgradable, unsigned *security)
{
    *obsolete = 9;
    *upgradable = 7;
    *security = 2;
    return GAUDIT_BACKEND_OK;
}

static gaudit_backend_status sourceless(gaudit_sourceless_fn fn, void *ctx)
{
    fn("a", "amd64", "1", GAUDIT_SOURCELESS_ABOVE_SOURCE, "0.9", ctx);
    fn("b", "amd64", "1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    fn("c", "amd64", "1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    /* Zoom's own package, and one by that name from someone else. */
    fn("zoom", "amd64", "7.2.5.6661", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    fn("zoom", "i386", "1.0", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    /* From NVIDIA's local copy, above Ubuntu's own version. */
    fn("libcublas-13-3", "amd64", "13.3.29-1", GAUDIT_SOURCELESS_ABOVE_SOURCE, "13.3.29-0ubuntu1", ctx);
    /* The installer's own package, which put the copy there. */
    fn("cuda-repo-ubuntu2604-13-3-local", "amd64", "13.3.1-1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    /* ClamUI's helper, which ClamUI keeps up to date itself. */
    fn("clamui-privileged-helper", "amd64", "0.5.1", GAUDIT_SOURCELESS_OTHER_SOURCE, NULL, ctx);
    /* An update for the release before, kept at the upgrade. */
    fn("libx11-6", "amd64", "2:1.8.13-1ubuntu0.1", GAUDIT_SOURCELESS_KEPT, "2:1.8.13-1", ctx);
    return GAUDIT_BACKEND_OK;
}

/* A local copy's index lists two packages; of those installed, one has the
 * very version it lists, one another. */
static gaudit_backend_status each_package(const char *index,
                                          void (*fn)(const char *, const char *, const char *, void *),
                                          void *ctx)
{
    if (index != NULL && strstr(index, "/cuda-repo-ubuntu2604-13-3-local/Packages") != NULL) {
        fn("cuda-toolkit-13-3", "amd64", "13.3.1-1", ctx);
        fn("libcublas-13-3", "amd64", "13.3.29-1", ctx);
    } else if (index == NULL) {
        fn("libcublas-13-3", "amd64", "13.3.29-1", ctx);
        fn("cuda-toolkit-13-3", "amd64", "13.3.0-1", ctx);
        fn("bash", "amd64", "5.3", ctx);
        fn("cuda-repo-ubuntu2604-13-3-local", "amd64", "13.3.1-1", ctx);
    } else {
        return GAUDIT_BACKEND_ERROR;
    }
    return GAUDIT_BACKEND_OK;
}

static const char *installed_zoom = "7.1.5.4332";
static int clamui_installed = 1;

static gaudit_backend_status details(const char *name, const char *arch, gaudit_package_details *out)
{
    memset(out, 0, sizeof *out);
    if (strcmp(name, "clamui-privileged-helper") == 0) {
        snprintf(out->maintainer, sizeof out->maintainer, "%s", "ClamUI Contributors <clamui@rooki.xyz>");
        snprintf(out->version, sizeof out->version, "%s", "0.5.1");
    }
    if (strcmp(name, "clamui") == 0 && clamui_installed)
        snprintf(out->version, sizeof out->version, "%s", "0.5.1");
    if (strcmp(name, "zoom") == 0) {
        int zoom = arch == NULL || strcmp(arch, "amd64") == 0;
        snprintf(out->maintainer, sizeof out->maintainer, "%s",
                 zoom ? "Zoom Communications, Inc. <https://support.zoom.com/hc>"
                      : "Someone Else <someone@example.org>");
        snprintf(out->version, sizeof out->version, "%s", zoom ? installed_zoom : "1.0");
    }
    return GAUDIT_BACKEND_OK;
}

static int compare(const char *a, const char *b)
{
    return strverscmp(a, b);
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
    .last_index_update = index_update, .security_sources = sources, .package_details = details,
    .version_compare = compare, .each_package = each_package,
};
static const gaudit_pkg_backend expected = { .name = "other", .package_system = "dpkg/apt" };
static const gaudit_pkg_backend bare = { .name = "bare" };

/* Collects from pkg; facts[] by key, seen[] how often each came. */
static gaudit_update_vendor vendors[GAUDIT_UPDATE_MAX_VENDOR];
static unsigned n_vendors;
static gaudit_update_local locals[GAUDIT_UPDATE_MAX_VENDOR];
static unsigned n_locals;
static gaudit_update_companion companions[GAUDIT_UPDATE_MAX_VENDOR];
static unsigned n_companions;

static int collect(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *exp,
                   gaudit_update_fact facts[GAUDIT_UPDATE_KEYS], int seen[GAUDIT_UPDATE_KEYS])
{
    n_vendors = 0;
    n_locals = 0;
    n_companions = 0;
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
        if (kind < 0 && !ended && n_vendors < GAUDIT_UPDATE_MAX_VENDOR
            && gaudit_update_parse_vendor(line, &vendors[n_vendors]) == 0) {
            n_vendors++;
        } else if (kind < 0 && !ended && n_locals < GAUDIT_UPDATE_MAX_VENDOR
                   && gaudit_update_parse_local(line, &locals[n_locals]) == 0) {
            n_locals++;
        } else if (kind < 0 && !ended && n_companions < GAUDIT_UPDATE_MAX_VENDOR
                   && gaudit_update_parse_companion(line, &companions[n_companions]) == 0) {
            n_companions++;
        } else if (kind == 1 && !ended) {
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

/* The vendor-latest line from these headers is as expected. */
static int latest(const gaudit_vendor_package *v, const char *headers, int status,
                  const char *version, int newer)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    if (out == NULL)
        return 0;
    int r = gaudit_updates_latest_from(&fake, v, headers, out);
    fclose(out);
    gaudit_update_latest l;
    int ok = r == 0 && gaudit_update_parse_latest(buf, &l) == 0 && l.status == status
             && strcmp(l.version, version) == 0 && l.newer == newer;
    if (!ok)
        fprintf(stderr, "latest: %s", buf != NULL ? buf : "(nothing)\n");
    free(buf);
    return ok;
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
    /* NVIDIA's local copy, in a /var made by the test. */
    char var[] = "/tmp/gaudit-var-XXXXXX";
    char cuda[256], index[300];
    if (mkdtemp(var) == NULL)
        return 1;
    snprintf(cuda, sizeof cuda, "%s/cuda-repo-ubuntu2604-13-3-local", var);
    snprintf(index, sizeof index, "%s/Packages", cuda);
    mkdir(cuda, 0755);
    FILE *pf = fopen(index, "w");
    if (pf != NULL)
        fclose(pf);
    gaudit_updates_local_reset();
    gaudit_updates_local_scan(&fake, var);
    gaudit_updates_flatpak_dirs(var, var);  /* no Flatpak apps there: only the package counts */
    CHECK(gaudit_updates_from_local("libcublas-13-3", "13.3.29-1"));
    CHECK(!gaudit_updates_from_local("cuda-toolkit-13-3", "13.3.0-1"));
    CHECK(gaudit_updates_from_local("cuda-repo-ubuntu2604-13-3-local", "13.3.1-1"));
    CHECK(collect(&fake, &expected, facts, seen) == 0);
    CHECK(n_locals == 1 && strcmp(locals[0].id, "cuda") == 0 && locals[0].packages == 2
          && strcmp(locals[0].made_for, "ubuntu2604") == 0
          && strcmp(locals[0].made_for_name, "Ubuntu 26.04") == 0 && strcmp(locals[0].version, "13.3") == 0);
    unlink(index);
    rmdir(cuda);
    rmdir(var);
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
    /* Zoom's package in its own group; the other "zoom" stays with the rest. */
    CHECK(facts[GAUDIT_UPDATE_SOURCELESS_KEPT].value == 1);
    CHECK(facts[GAUDIT_UPDATE_SOURCELESS].value == 5
          && facts[GAUDIT_UPDATE_SOURCELESS_ABOVE].value == 1
          && facts[GAUDIT_UPDATE_SOURCELESS_LEFTOVER].value == 0
          && facts[GAUDIT_UPDATE_SOURCELESS_OTHER].value == 3
          && facts[GAUDIT_UPDATE_SOURCELESS_VENDOR].value == 4);
    CHECK(n_companions == 1 && strcmp(companions[0].package, "clamui-privileged-helper") == 0
          && companions[0].present == 1 && strcmp(companions[0].manager, "ClamUI") == 0);
    /* ClamUI gone: the helper is still shown, as one nothing updates now. */
    clamui_installed = 0;
    CHECK(collect(&fake, &expected, facts, seen) == 0);
    CHECK(n_companions == 1 && companions[0].present == 0);
    clamui_installed = 1;
    CHECK(n_vendors == 1 && strcmp(vendors[0].id, "zoom") == 0 && strcmp(vendors[0].title, "Zoom") == 0
          && strcmp(vendors[0].version, "7.2.5.6661") == 0);
    CHECK(facts[GAUDIT_UPDATE_SECURITY_MIRROR].value == 1
          && strcmp(facts[GAUDIT_UPDATE_SECURITY_MIRROR].text, "mirror.example.org") == 0);

    /* The vendor line round-trips and refuses what it should. */
    gaudit_update_vendor v = { "zoom", "Zoom", "Zoom", "7.2.5.6661" }, w;
    CHECK(gaudit_update_format_vendor(&v, line, sizeof line) == 0
          && gaudit_update_parse_vendor(line, &w) == 0 && strcmp(w.version, v.version) == 0);
    CHECK(gaudit_update_parse_line(line, &g, &n) == -1);
    CHECK(gaudit_update_parse_vendor("(vendor-package (id \"\") (title \"\") (vendor \"\") (version \"\"))", &w) == -1);
    CHECK(gaudit_update_parse_vendor("(vendor-package (id \"zoom\") (title \"Zoom\") (vendor \"Zoom\"))", &w) == -1);
    CHECK(gaudit_update_parse_vendor("(fact (key \"pending\") (status 0) (value 0) (text \"\"))", &w) == -1);

    /* The download line round-trips, also with a long home folder, and
     * refuses a path without success or success without a path. */
    gaudit_update_download dl = { .id = "zoom", .status = 0 }, dm;
    snprintf(dl.path, sizeof dl.path, "/home/%0150d/.cache/gaudit/vendor/zoom.deb", 0);
    char dline[1024];
    CHECK(gaudit_update_format_download(&dl, dline, sizeof dline) == 0
          && gaudit_update_parse_download(dline, &dm) == 0 && dm.status == 0
          && strcmp(dm.path, dl.path) == 0 && dm.reason[0] == '\0');
    gaudit_update_download df = { .id = "zoom", .status = 1, .reason = "fetch-8" };
    CHECK(gaudit_update_format_download(&df, dline, sizeof dline) == 0
          && gaudit_update_parse_download(dline, &dm) == 0 && strcmp(dm.reason, "fetch-8") == 0);
    CHECK(gaudit_update_parse_download("(vendor-download (id \"zoom\") (status 0) (path \"\") (reason \"\"))", &dm) == -1);
    CHECK(gaudit_update_parse_download("(vendor-download (id \"zoom\") (status 1) (path \"/x\") (reason \"\"))", &dm) == -1);

    /* The local copy's line round-trips; folder names are read strictly. */
    gaudit_update_local lc = { "cuda", "CUDA", "NVIDIA", "13.3", "ubuntu2604", "Ubuntu 26.04",
                               "ubuntu2610", "ubuntu2604", 42 }, ld;
    CHECK(gaudit_update_format_local(&lc, dline, sizeof dline) == 0
          && gaudit_update_parse_local(dline, &ld) == 0 && ld.packages == 42
          && strcmp(ld.previous, "ubuntu2604") == 0);
    char rel[16], ver[16];
    CHECK(gaudit_vendor_local_match("cuda-repo-ubuntu2604-13-3-local", rel, sizeof rel, ver, sizeof ver) != NULL
          && strcmp(rel, "ubuntu2604") == 0 && strcmp(ver, "13.3") == 0);
    CHECK(gaudit_vendor_local_match("cuda-repo-debian13-12-4-local", rel, sizeof rel, ver, sizeof ver) != NULL
          && strcmp(rel, "debian13") == 0 && strcmp(ver, "12.4") == 0);
    const char *bad_dirs[] = { "cuda-repo-ubuntu2604-local", "cuda-repo--13-3-local", "cuda-repo-2604-13-3-local",
                               "cuda-repo-ubuntu2604-13--3-local", "cuda-repo-ubuntu2604-13-3-locals",
                               "cuda-repo-ubuntu2604-13-x-local", "other-repo-ubuntu2604-13-3-local" };
    for (size_t i = 0; i < sizeof bad_dirs / sizeof bad_dirs[0]; i++)
        CHECK(gaudit_vendor_local_match(bad_dirs[i], rel, sizeof rel, ver, sizeof ver) == NULL);
    const gaudit_vendor_local *cl = gaudit_vendor_local_find("cuda");
    CHECK(gaudit_vendor_local_has_network(cl, "ubuntu2604") && !gaudit_vendor_local_has_network(cl, "ubuntu2610"));
    char rid[16], rname[32];
    CHECK(gaudit_vendor_release_id("ubuntu", "26.10", rid, sizeof rid) && strcmp(rid, "ubuntu2610") == 0);
    CHECK(gaudit_vendor_release_id("debian", "13", rid, sizeof rid) && strcmp(rid, "debian13") == 0);
    CHECK(!gaudit_vendor_release_id("fedora", "45", rid, sizeof rid));
    gaudit_vendor_release_name("ubuntu2604", rname, sizeof rname);
    CHECK(strcmp(rname, "Ubuntu 26.04") == 0);

    /* The companion's line round-trips; it is known by name and maker. */
    gaudit_update_companion cc = { "clamui-helper", "clamui-privileged-helper", "ClamUI", "0.5.1", 1 }, cd;
    CHECK(gaudit_update_format_companion(&cc, dline, sizeof dline) == 0
          && gaudit_update_parse_companion(dline, &cd) == 0 && cd.present == 1);
    CHECK(gaudit_vendor_companion_match("clamui-privileged-helper", "ClamUI Contributors <x@y>") != NULL);
    CHECK(gaudit_vendor_companion_match("clamui-privileged-helper", "Someone <x@y>") == NULL);

    /* The table: by name and maker together, the address left out. */
    CHECK(gaudit_vendor_match("zoom", "Zoom Communications, Inc. <https://support.zoom.com/hc>") != NULL);
    CHECK(gaudit_vendor_match("zoom", "Zoom Communications, Inc.") != NULL);
    CHECK(gaudit_vendor_match("zoom", "Zoom Communications, Inc. Evil <x@y>") == NULL);
    CHECK(gaudit_vendor_match("zoom", "Zoom Communications <x@y>") == NULL);
    CHECK(gaudit_vendor_match("zoomx", "Zoom Communications, Inc. <x@y>") == NULL);
    CHECK(gaudit_vendor_match("zoom", "") == NULL && gaudit_vendor_match(NULL, "x") == NULL);
    CHECK(gaudit_vendor_find("zoom") != NULL && gaudit_vendor_find("nope") == NULL);

    /* The newest version, from the headers wget or curl gave. */
    const gaudit_vendor_package *zoom = gaudit_vendor_find("zoom");
    const char *wget_out =
        "HTTP request sent, awaiting response... \n  HTTP/1.1 302 Found\n"
        "  location: https://cdn.zoom.us/prod/7.2.5.6661/zoom_amd64.deb\n  Server: cloudflare\n";
    const char *curl_out = "HTTP/2 302 \r\nlocation: https://cdn.zoom.us/prod/7.2.5.6661/zoom_amd64.deb\r\n";
    CHECK(latest(zoom, wget_out, 0, "7.2.5.6661", 1));
    CHECK(latest(zoom, curl_out, 0, "7.2.5.6661", 1));
    installed_zoom = "7.2.5.6661";
    CHECK(latest(zoom, curl_out, 0, "7.2.5.6661", 0));
    installed_zoom = "7.1.5.4332";
    /* Only exactly the vendor's address; nothing else counts as found out. */
    const char *bad_out[] = {
        "",
        "Location: https://evil.example.org/prod/9.9.9/zoom_amd64.deb\n",
        "Location: https://cdn.zoom.us/prod/9.9.9/zoom_amd64.deb.exe\n",
        "Location: http://cdn.zoom.us/prod/9.9.9/zoom_amd64.deb\n",
        "Location: https://cdn.zoom.us/prod/../x/zoom_amd64.deb\n",
        "Location: https://cdn.zoom.us/prod/9..9/zoom_amd64.deb\n",
        "Location: https://cdn.zoom.us/prod/9.9.9-beta/zoom_amd64.deb\n",
        "X-Location: https://cdn.zoom.us/prod/9.9.9/zoom_amd64.deb\n",
    };
    for (size_t i = 0; i < sizeof bad_out / sizeof bad_out[0]; i++)
        CHECK(latest(zoom, bad_out[i], 1, "", 0));
    /* The line round-trips and refuses what it should. */
    gaudit_update_latest l = { "zoom", 0, "7.2.5.6661", "7.1.5.4332", 1 }, m;
    CHECK(gaudit_update_format_latest(&l, line, sizeof line) == 0
          && gaudit_update_parse_latest(line, &m) == 0 && m.newer == 1 && strcmp(m.version, l.version) == 0);
    CHECK(gaudit_update_parse_latest("(vendor-latest (id \"zoom\") (status 1) (version \"\") (installed \"\") (newer 1))", &m) == -1);
    CHECK(gaudit_update_parse_latest("(vendor-latest (id \"zoom\") (status 2) (version \"\") (installed \"\") (newer 0))", &m) == -1);

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
