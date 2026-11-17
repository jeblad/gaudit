/* SPDX-License-Identifier: GPL-3.0-only */
#include "vendor.h"

#include <stdio.h>
#include <string.h>

static const gaudit_vendor_key zoom_keys[] = {
    { "84C365D6CC9A4886CA926BCC4F2197399706AC24", "6.7.5",
      "Zoom's download page (zoom.us/download) and its key file package-signing-key-6-7-5.pub, "
      "2026-11-16; checked against a package signed 2026-10-30" },
};

static const gaudit_vendor_package table[] = {
    { "zoom", "zoom", "Zoom Communications, Inc.", "Zoom", "Zoom",
      "https://zoom.us/download?os=linux", "us.zoom.Zoom",
      "https://zoom.us/client/latest/zoom_amd64.deb", "https://cdn.zoom.us/prod/", "/zoom_amd64.deb",
      "zoom.gpg",
      zoom_keys, sizeof zoom_keys / sizeof zoom_keys[0],
      GAUDIT_FLATPAK_UNVERIFIED, "flathub.org/apps/us.zoom.Zoom, 2026-11-17", NULL, NULL },
    /* Discord signs nothing: no _gpgbuilder in the package, nothing beside
     * it (checked on 1.0.169, 2026-11-16). So no key: gAudit may say a newer
     * version is out, but never installs it. */
    { "discord", "discord", "Discord Maintainer Team", "Discord", "Discord",
      "https://discord.com/download", "com.discordapp.Discord",
      "https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable"
      "&platform=linux&arch=x64",
      "https://stable.dl2.discordapp.net/distro/app/stable/linux/x64/", "/Discord.deb",
      NULL, NULL, 0, GAUDIT_FLATPAK_NOT_CHECKED, NULL, NULL, NULL },
    /* Obsidian signs nothing either: no _gpgbuilder, and its GitHub
     * release has no signature beside the package (checked on 1.15.1,
     * 2026-11-17). Maintainer is "Dynalist Inc.", without an address. The
     * newest version is the release tag GitHub's "latest" redirects to.
     * Its own snap is the one to name; the Flatpak is made by others. */
    { "obsidian", "obsidian", "Dynalist Inc.", "Obsidian", "Obsidian",
      "https://obsidian.md/download", "md.obsidian.Obsidian",
      "https://github.com/obsidianmd/obsidian-releases/releases/latest",
      "https://github.com/obsidianmd/obsidian-releases/releases/tag/v", "",
      NULL, NULL, 0,
      GAUDIT_FLATPAK_UNVERIFIED, "community maintained on Flathub, John, 2026-11-17",
      "obsidian", "the Snap Store, published by Obsidian, John, 2026-11-17" },
};

const gaudit_vendor_package *gaudit_vendor_match(const char *package, const char *maintainer)
{
    if (package == NULL || maintainer == NULL)
        return NULL;
    /* The name part of "Name <address>", without the space before "<". */
    const char *lt = strchr(maintainer, '<');
    size_t n = lt != NULL ? (size_t)(lt - maintainer) : strlen(maintainer);
    while (n > 0 && maintainer[n - 1] == ' ')
        n--;
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].package, package) == 0 && strlen(table[i].maker) == n
            && strncmp(table[i].maker, maintainer, n) == 0)
            return &table[i];
    return NULL;
}

const gaudit_vendor_package *gaudit_vendor_find(const char *id)
{
    for (size_t i = 0; id != NULL && i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].id, id) == 0)
            return &table[i];
    return NULL;
}

int gaudit_vendor_name_known(const char *package)
{
    for (size_t i = 0; package != NULL && i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].package, package) == 0)
            return 1;
    return 0;
}

int gaudit_vendor_version_from(const gaudit_vendor_package *p, const char *location,
                               char *version, size_t len)
{
    if (p == NULL || p->prefix == NULL || p->suffix == NULL || location == NULL || version == NULL
        || len == 0)
        return 0;
    size_t pl = strlen(p->prefix), sl = strlen(p->suffix), ll = strlen(location);
    if (ll <= pl + sl || strncmp(location, p->prefix, pl) != 0
        || strcmp(location + ll - sl, p->suffix) != 0)
        return 0;
    const char *v = location + pl;
    size_t vl = ll - pl - sl;
    if (vl > 32 || vl >= len || v[0] == '.' || v[vl - 1] == '.')
        return 0;
    for (size_t i = 0; i < vl; i++)
        if (!((v[i] >= '0' && v[i] <= '9') || (v[i] == '.' && v[i + 1] != '.')))
            return 0;
    memcpy(version, v, vl);
    version[vl] = '\0';
    return 1;
}

int gaudit_vendor_plain_version(const char *v)
{
    size_t n = v != NULL ? strlen(v) : 0;
    if (n == 0 || n > 32 || v[0] == '.' || v[n - 1] == '.')
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!((v[i] >= '0' && v[i] <= '9') || (v[i] == '.' && v[i + 1] != '.')))
            return 0;
    return 1;
}

int gaudit_vendor_verify_args_ok(const char *id, const char *version, const char *path)
{
    const gaudit_vendor_package *p = gaudit_vendor_find(id);
    if (p == NULL || p->key_file == NULL || !gaudit_vendor_plain_version(version) || path == NULL
        || path[0] != '/' || strlen(path) > 1024)
        return 0;
    char suffix[128];
    snprintf(suffix, sizeof suffix, "/.cache/gaudit/vendor/%s.deb", p->id);
    size_t pl = strlen(path), sl = strlen(suffix);
    if (pl <= sl || strcmp(path + pl - sl, suffix) != 0)
        return 0;
    /* No "." or ".." part, no empty one. */
    for (const char *c = path; *c != '\0'; c++)
        if (c[0] == '/' && (c[1] == '/' || (c[1] == '.' && (c[2] == '/' || c[2] == '\0'
                                                            || (c[2] == '.' && (c[3] == '/' || c[3] == '\0'))))))
            return 0;
    for (const char *c = path; *c != '\0'; c++)
        if ((unsigned char)*c <= 0x20 || *c == 0x7f)  /* no spaces: one word on the helper's line */
            return 0;
    return 1;
}


/* --- Local copies of a vendor's source ------------------------------------- */

/* NVIDIA's network sources for x86_64, checked at
 * developer.download.nvidia.com/compute/cuda/repos/<release>/x86_64/InRelease
 * on 2026-11-16 (none for ubuntu2504, ubuntu2510, ubuntu2610). */
static const char *const cuda_network[] = {
    "ubuntu2004", "ubuntu2204", "ubuntu2404", "ubuntu2604", "debian11", "debian12", "debian13", NULL,
};

static const gaudit_vendor_local locals[] = {
    { "cuda", "CUDA", "NVIDIA", "cuda-repo-", "-local", "https://developer.nvidia.com/cuda-downloads",
      "cuda-toolkit-", cuda_network,
      "developer.download.nvidia.com/compute/cuda/repos/, 2026-11-16" },
};

const gaudit_vendor_local *gaudit_vendor_local_find(const char *id)
{
    for (size_t i = 0; id != NULL && i < sizeof locals / sizeof locals[0]; i++)
        if (strcmp(locals[i].id, id) == 0)
            return &locals[i];
    return NULL;
}

const gaudit_vendor_local *gaudit_vendor_local_at(size_t n)
{
    return n < sizeof locals / sizeof locals[0] ? &locals[n] : NULL;
}

const gaudit_vendor_local *gaudit_vendor_local_match(const char *dir_name, char *release,
                                                     size_t release_len, char *version,
                                                     size_t version_len)
{
    if (dir_name == NULL || release == NULL || version == NULL)
        return NULL;
    for (size_t i = 0; i < sizeof locals / sizeof locals[0]; i++) {
        const gaudit_vendor_local *v = &locals[i];
        size_t pl = strlen(v->dir_prefix), sl = strlen(v->dir_suffix), nl = strlen(dir_name);
        if (nl <= pl + sl || strncmp(dir_name, v->dir_prefix, pl) != 0
            || strcmp(dir_name + nl - sl, v->dir_suffix) != 0)
            continue;
        /* <letters><digits>-<digits>(-<digits>)* */
        const char *p = dir_name + pl, *end = dir_name + nl - sl;
        const char *dash = memchr(p, '-', (size_t)(end - p));
        if (dash == NULL || dash == p || (size_t)(dash - p) >= release_len)
            continue;
        size_t letters = 0;
        while (p + letters < dash && p[letters] >= 'a' && p[letters] <= 'z')
            letters++;
        int ok = letters > 0 && p + letters < dash;
        for (const char *c = p + letters; ok && c < dash; c++)
            ok = *c >= '0' && *c <= '9';
        size_t vl = (size_t)(end - dash - 1);
        ok = ok && vl > 0 && vl < version_len && dash[1] != '-' && end[-1] != '-';
        for (const char *c = dash + 1; ok && c < end; c++)
            ok = (*c >= '0' && *c <= '9') || (*c == '-' && c[1] != '-');
        if (!ok)
            continue;
        snprintf(release, release_len, "%.*s", (int)(dash - p), p);
        snprintf(version, version_len, "%.*s", (int)vl, dash + 1);
        for (char *c = version; *c != '\0'; c++)
            if (*c == '-')
                *c = '.';
        return v;
    }
    return NULL;
}

int gaudit_vendor_local_has_network(const gaudit_vendor_local *v, const char *release)
{
    for (size_t i = 0; v != NULL && release != NULL && v->network[i] != NULL; i++)
        if (strcmp(v->network[i], release) == 0)
            return 1;
    return 0;
}

int gaudit_vendor_release_id(const char *id, const char *version_id, char *out, size_t len)
{
    if (id == NULL || version_id == NULL || out == NULL || len == 0
        || (strcmp(id, "ubuntu") != 0 && strcmp(id, "debian") != 0) || version_id[0] == '\0')
        return 0;
    size_t n = (size_t)snprintf(out, len, "%s", id);
    for (const char *c = version_id; *c != '\0' && n + 1 < len; c++) {
        if (*c == '.')
            continue;
        if (*c < '0' || *c > '9')
            return 0;
        out[n++] = *c;
        out[n] = '\0';
    }
    return 1;
}

void gaudit_vendor_release_name(const char *release, char *out, size_t len)
{
    if (out == NULL || len == 0)
        return;
    if (release != NULL && strncmp(release, "ubuntu", 6) == 0 && strlen(release) == 10)
        snprintf(out, len, "Ubuntu %.2s.%.2s", release + 6, release + 8);
    else if (release != NULL && strncmp(release, "debian", 6) == 0 && release[6] != '\0')
        snprintf(out, len, "Debian %s", release + 6);
    else
        snprintf(out, len, "%s", release != NULL ? release : "");
}

/* --- Packages another program keeps up to date ------------------------------ */

/* ClamUI installs its helper itself ("Install Helper": the signed release
 * asset from GitHub, checked, then installed through polkit) and needs the
 * very same version, so an update of ClamUI brings the helper's; from
 * ClamUI's installation guide and debian/DEBIAN/control.helper, 2026-11-16. */
static const gaudit_vendor_companion companions[] = {
    { "clamui-helper", "clamui-privileged-helper", "ClamUI Contributors", "ClamUI",
      "io.github.linx_systems.ClamUI", "clamui" },
};

static int same_maker(const char *maker, const char *maintainer)
{
    if (maker == NULL || maintainer == NULL)
        return 0;
    const char *lt = strchr(maintainer, '<');
    size_t n = lt != NULL ? (size_t)(lt - maintainer) : strlen(maintainer);
    while (n > 0 && maintainer[n - 1] == ' ')
        n--;
    return strlen(maker) == n && strncmp(maker, maintainer, n) == 0;
}

const gaudit_vendor_companion *gaudit_vendor_companion_match(const char *package,
                                                             const char *maintainer)
{
    for (size_t i = 0; package != NULL && i < sizeof companions / sizeof companions[0]; i++)
        if (strcmp(companions[i].package, package) == 0 && same_maker(companions[i].maker, maintainer))
            return &companions[i];
    return NULL;
}

const gaudit_vendor_companion *gaudit_vendor_companion_find(const char *id)
{
    for (size_t i = 0; id != NULL && i < sizeof companions / sizeof companions[0]; i++)
        if (strcmp(companions[i].id, id) == 0)
            return &companions[i];
    return NULL;
}

int gaudit_vendor_companion_name_known(const char *package)
{
    for (size_t i = 0; package != NULL && i < sizeof companions / sizeof companions[0]; i++)
        if (strcmp(companions[i].package, package) == 0)
            return 1;
    return 0;
}
