/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cloud-folders.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE (1 << 20)

/* The gathering folder by language (John, 2026-11-19), and the words for an
 * encrypted service's two mounts. nb and nn reviewed by John; da and sv
 * from him too, to be checked by a native speaker before they ship. */
const gaudit_cloud_language gaudit_cloud_languages[] = {
    { "en", "Cloud", "private", "shared folder" },
    { "nb", "Skytjenester", "privat", "delt mappe" },
    { "nn", "Skytenester", "privat", "delt mappe" },
    { "da", "Cloudtjenester", "privat", "delt mappe" },
    { "sv", "Molntjänster", "privat", "delad mapp" },
};
const unsigned gaudit_cloud_languages_count =
    sizeof gaudit_cloud_languages / sizeof gaudit_cloud_languages[0];

/* Names a gathering folder has been seen with besides the table's. */
static const char *const gathering_seen[] = { "SkyTjenester" };

const gaudit_cloud_language *gaudit_cloud_language_by_code(const char *lang)
{
    for (unsigned i = 0; lang != NULL && i < gaudit_cloud_languages_count; i++)
        if (strcmp(gaudit_cloud_languages[i].lang, lang) == 0)
            return &gaudit_cloud_languages[i];
    return NULL;
}

const gaudit_cloud_language *gaudit_cloud_language_for(const char *locale)
{
    char code[8] = "";
    if (locale != NULL) {
        size_t n = strcspn(locale, "_.@\n");
        if (n > 0 && n < sizeof code)
            memcpy(code, locale, n), code[n] = '\0';
    }
    if (strcmp(code, "no") == 0)   /* the old code for Norwegian, as Bokmål */
        snprintf(code, sizeof code, "nb");
    const gaudit_cloud_language *l = gaudit_cloud_language_by_code(code);
    return l != NULL ? l : &gaudit_cloud_languages[0];
}

int gaudit_cloud_gathering_known(const char *name)
{
    for (unsigned i = 0; name != NULL && i < gaudit_cloud_languages_count; i++)
        if (strcmp(gaudit_cloud_languages[i].gathering, name) == 0)
            return 1;
    for (size_t i = 0; name != NULL && i < sizeof gathering_seen / sizeof gathering_seen[0]; i++)
        if (strcmp(gathering_seen[i], name) == 0)
            return 1;
    return 0;
}

/* Every known name, the table's then those seen: i from 0 until NULL. */
static const char *gathering_name(size_t i)
{
    if (i < gaudit_cloud_languages_count)
        return gaudit_cloud_languages[i].gathering;
    i -= gaudit_cloud_languages_count;
    return i < sizeof gathering_seen / sizeof gathering_seen[0] ? gathering_seen[i] : NULL;
}

static char *read_text(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE) {
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    size_t got = 0;
    while (buf != NULL && got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (buf != NULL)
        buf[got] = '\0';
    return buf;
}

static int is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* One field of a /proc/self/mounts line, its octal escapes (\040 for a
 * space) undone; the rest of the line after it. NULL when it does not fit. */
static const char *mount_field(const char *at, char *out, size_t len)
{
    while (*at == ' ' || *at == '\t')
        at++;
    size_t n = 0;
    while (*at != '\0' && *at != ' ' && *at != '\t' && *at != '\n') {
        char c = *at++;
        if (c == '\\' && at[0] >= '0' && at[0] <= '3' && at[1] >= '0' && at[1] <= '7'
            && at[2] >= '0' && at[2] <= '7') {
            c = (char)((at[0] - '0') * 64 + (at[1] - '0') * 8 + (at[2] - '0'));
            at += 3;
        }
        if (n + 1 >= len)
            return NULL;
        out[n++] = c;
    }
    out[n] = '\0';
    return n > 0 ? at : NULL;
}

/* A mounts line's source, mount point and type; 1 when all three are there. */
static int mount_line(const char *line, char src[256], char dst[512], char fs[64])
{
    const char *at = mount_field(line, src, 256);
    at = at != NULL ? mount_field(at, dst, 512) : NULL;
    at = at != NULL ? mount_field(at, fs, 64) : NULL;
    return at != NULL;
}

/* An absolute path without control characters. */
static int plain_path(const char *p)
{
    if (p == NULL || p[0] != '/' || strlen(p) >= 512)
        return 0;
    for (const unsigned char *c = (const unsigned char *)p; *c != '\0'; c++)
        if (*c < 0x20 || *c == 0x7f)
            return 0;
    return 1;
}

static void add(gaudit_cloud_findings *out, const char *client, const char *service,
                gaudit_cloud_how how, const char *path, const char *name)
{
    if (path != NULL && path[0] != '\0' && !plain_path(path))
        return;
    for (unsigned i = 0; i < out->n; i++)   /* the same folder found twice (a mount too) */
        if (path != NULL && path[0] != '\0' && strcmp(out->f[i].path, path) == 0
            && strcmp(out->f[i].client, client) == 0)
            return;
    if (out->n >= GAUDIT_CLOUD_MAX) {
        out->more = 1;
        return;
    }
    gaudit_cloud_finding *f = &out->f[out->n++];
    memset(f, 0, sizeof *f);
    snprintf(f->client, sizeof f->client, "%s", client);
    snprintf(f->service, sizeof f->service, "%s", service);
    f->how = how;
    snprintf(f->path, sizeof f->path, "%s", path != NULL ? path : "");
    snprintf(f->name, sizeof f->name, "%.127s", name != NULL ? name : "");
    for (char *c = f->name; *c != '\0'; c++)
        if ((unsigned char)*c < 0x20 || *c == 0x7f)
            *c = '?';
}

/* --- Dropbox: ~/.dropbox/info.json ------------------------------------------- */

unsigned gaudit_cloud_dropbox_paths(const char *json, char out[][512], unsigned max)
{
    unsigned n = 0;
    for (const char *p = json; p != NULL && n < max && (p = strstr(p, "\"path\"")) != NULL;) {
        p += 6;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (*p++ != ':')
            continue;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (*p++ != '"')
            continue;
        char v[512];
        size_t k = 0;
        int ok = 1;
        for (; *p != '\0' && *p != '"'; p++) {
            char c = *p;
            if (c == '\\') {
                p++;
                if (*p == '"' || *p == '\\' || *p == '/')
                    c = *p;
                else
                    ok = 0;  /* \u and the like: not taken, never guessed */
                if (*p == '\0')
                    break;
            }
            if (k + 1 >= sizeof v)
                ok = 0;
            else
                v[k++] = c;
        }
        v[k] = '\0';
        if (ok && plain_path(v))
            snprintf(out[n++], 512, "%s", v);
    }
    return n;
}

/* --- Nextcloud and ownCloud: their .cfg, in INI form ------------------------- */

/* Every "...Folders\N\localPath=..." value, as the clients write it. */
static void qt_cfg_folders(gaudit_cloud_findings *out, const char *path, const char *client)
{
    char *text = read_text(path);
    for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        size_t kl = strlen(line);
        if (kl < 10 || strcmp(line + kl - 10, "\\localPath") != 0 || strstr(line, "olders") == NULL)
            continue;
        char *v = eq + 1;
        size_t vl = strlen(v);
        while (vl > 0 && (v[vl - 1] == '\r' || v[vl - 1] == ' '))
            v[--vl] = '\0';
        if (vl >= 2 && v[0] == '"' && v[vl - 1] == '"') {
            v[vl - 1] = '\0';
            v++;
        }
        vl = strlen(v);
        while (vl > 1 && v[vl - 1] == '/')
            v[--vl] = '\0';
        add(out, client, client, GAUDIT_CLOUD_FOLDER, v, NULL);
    }
    free(text);
}

/* --- onedrive: ~/.config/onedrive/config ------------------------------------- */

static void onedrive(gaudit_cloud_findings *out, const char *home, const char *root)
{
    char cfg[1100], dir[1024], bin[1024];
    snprintf(dir, sizeof dir, "%s/.config/onedrive", home);
    snprintf(cfg, sizeof cfg, "%s/config", dir);
    snprintf(bin, sizeof bin, "%s/usr/bin/onedrive", root);
    char sync_dir[512] = "";
    char *text = read_text(cfg);
    for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        while (*line == ' ' || *line == '\t')
            line++;
        if (strncmp(line, "sync_dir", 8) != 0)
            continue;
        char *q1 = strchr(line, '"'), *q2 = q1 != NULL ? strchr(q1 + 1, '"') : NULL;
        if (q2 == NULL)
            continue;
        *q2 = '\0';
        const char *v = q1 + 1;
        if (v[0] == '~' && (v[1] == '/' || v[1] == '\0'))
            snprintf(sync_dir, sizeof sync_dir, "%s%s", home, v + 1);
        else
            snprintf(sync_dir, sizeof sync_dir, "%s", v);
    }
    free(text);
    if (sync_dir[0] == '\0' && is_dir(dir)) {
        /* Set up (its folder is there) but without a config file: the default. */
        snprintf(sync_dir, sizeof sync_dir, "%s/OneDrive", home);
    }
    if (sync_dir[0] != '\0')
        add(out, "onedrive", "onedrive", GAUDIT_CLOUD_FOLDER, sync_dir, NULL);
    else if (exists(bin))
        add(out, "onedrive", "onedrive", GAUDIT_CLOUD_INSTALLED, NULL, NULL);
}

/* --- Insync: ~/Insync/<account>/<service> ------------------------------------- */

static void insync(gaudit_cloud_findings *out, const char *home)
{
    static const struct { const char *folder, *service; } kinds[] = {
        { "Google Drive", "google-drive" }, { "OneDrive", "onedrive" }, { "Dropbox", "dropbox" },
    };
    char base[1024];
    snprintf(base, sizeof base, "%s/Insync", home);
    DIR *d = opendir(base);
    if (d == NULL)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
            char p[1536];
            snprintf(p, sizeof p, "%s/%s/%s", base, de->d_name, kinds[k].folder);
            if (is_dir(p))
                add(out, "insync", kinds[k].service, GAUDIT_CLOUD_FOLDER, p, de->d_name);
        }
    }
    closedir(d);
}

/* --- rclone: names and types only --------------------------------------------- */

typedef struct {
    char name[128];
    char type[32];
    char remote[160];  /* a crypt remote's "remote", e.g. "gdrive:secret" */
} remote;

static const char *rclone_service(const char *type)
{
    static const struct { const char *type, *service; } map[] = {
        { "drive", "google-drive" }, { "onedrive", "onedrive" }, { "dropbox", "dropbox" },
        { "jottacloud", "jottacloud" }, { "mega", "mega" }, { "pcloud", "pcloud" },
        { "protondrive", "proton-drive" }, { "webdav", "webdav" },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strcmp(type, map[i].type) == 0)
            return map[i].service;
    return NULL;  /* object storage and others: not taken in */
}

static unsigned rclone_remotes(const char *home, remote *rs, unsigned max, int *unreadable)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/.config/rclone/rclone.conf", home);
    char *text = read_text(path);
    if (text == NULL) {
        *unreadable = exists(path);
        return 0;
    }
    unsigned n = 0;
    if (strncmp(text, "# Encrypted rclone configuration", 32) == 0
        || strstr(text, "RCLONE_ENCRYPT_V0:") != NULL)
        *unreadable = 1;  /* encrypted by rclone: good, and nothing to read */
    for (char *line = text, *next; !*unreadable && line != NULL && *line != '\0'; line = next) {
        next = strchr(line, '\n');
        if (next != NULL)
            *next++ = '\0';
        while (*line == ' ' || *line == '\t')
            line++;
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == '\r' || line[ll - 1] == ' '))
            line[--ll] = '\0';
        if (line[0] == '[' && ll > 2 && line[ll - 1] == ']') {
            if (n >= max)
                break;
            memset(&rs[n], 0, sizeof rs[n]);
            snprintf(rs[n].name, sizeof rs[n].name, "%.*s", (int)(ll - 2), line + 1);
            n++;
            continue;
        }
        if (n == 0)
            continue;
        /* Only these two keys are ever looked at. */
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;
        char *k = line, *v = eq + 1;
        *eq = '\0';
        size_t kl = strlen(k);
        while (kl > 0 && (k[kl - 1] == ' ' || k[kl - 1] == '\t'))
            k[--kl] = '\0';
        while (*v == ' ' || *v == '\t')
            v++;
        if (strcmp(k, "type") == 0)
            snprintf(rs[n - 1].type, sizeof rs[n - 1].type, "%.31s", v);
        else if (strcmp(k, "remote") == 0 && strcmp(rs[n - 1].type, "crypt") == 0)
            snprintf(rs[n - 1].remote, sizeof rs[n - 1].remote, "%.159s", v);
    }
    free(text);
    return n;
}

static void rclone(gaudit_cloud_findings *out, const char *home, const char *mounts_path)
{
    remote rs[32];
    int unreadable = 0;
    unsigned n = rclone_remotes(home, rs, 32, &unreadable);
    out->rclone_unreadable = unreadable;
    /* Which remotes a crypt remote covers. */
    int covered[32] = { 0 };
    int by[32];
    for (unsigned i = 0; i < n; i++) {
        if (strcmp(rs[i].type, "crypt") != 0)
            continue;
        size_t bl = strcspn(rs[i].remote, ":");
        for (unsigned j = 0; j < n; j++)
            if (j != i && strlen(rs[j].name) == bl && strncmp(rs[j].name, rs[i].remote, bl) == 0)
                covered[j] = 1, by[j] = (int)i;
    }
    /* Mounted remotes: "name:" in /proc/self/mounts, type fuse.rclone; a
     * remote is mounted also when the crypt remote over it is (what is
     * mounted then is "<crypt>:", the files go to the remote under it). */
    char *mounts = read_text(mounts_path);
    for (unsigned i = 0; i < n; i++) {
        const char *service = rclone_service(rs[i].type);
        if (service == NULL)
            continue;
        const char *names[2] = { rs[i].name, covered[i] ? rs[by[i]].name : NULL };
        char mount[512] = "";
        int crypt_mounted = 0;
        const char *line = mounts;
        while (line != NULL && *line != '\0') {
            char src[256], dst[512], fs[64];
            if (mount_line(line, src, dst, fs) && strcmp(fs, "fuse.rclone") == 0)
                for (int k = 0; k < 2; k++)
                    if (names[k] != NULL && strncmp(src, names[k], strlen(names[k])) == 0
                        && src[strlen(names[k])] == ':' && (k == 1 || !crypt_mounted)) {
                        /* Both mounted (a private and a shareable disk): the
                         * encrypted one is where the files are meant to go. */
                        snprintf(mount, sizeof mount, "%s", dst);
                        crypt_mounted = k == 1;
                    }
            line = strchr(line, '\n');
            if (line != NULL)
                line++;
        }
        unsigned before = out->n;
        add(out, "rclone", service, mount[0] != '\0' ? GAUDIT_CLOUD_MOUNT : GAUDIT_CLOUD_SETUP,
            mount, rs[i].name);
        if (out->n > before) {
            out->f[out->n - 1].encrypted = covered[i];
            if (covered[i]) {
                gaudit_cloud_finding *f = &out->f[out->n - 1];
                snprintf(f->via, sizeof f->via, "%s", rs[by[i]].name);
                /* "gdrive:vault/" -> "vault": where on the remote the
                 * encrypted files are, slashes at either end left out. */
                const char *u = strchr(rs[by[i]].remote, ':');
                u = u != NULL ? u + 1 : "";
                while (*u == '/')
                    u++;
                snprintf(f->under, sizeof f->under, "%s", u);
                size_t ul = strlen(f->under);
                while (ul > 0 && f->under[ul - 1] == '/')
                    f->under[--ul] = '\0';
            }
        }
    }
    free(mounts);
}

/* --- pCloud: its mount ------------------------------------------------------------ */

static void pcloud(gaudit_cloud_findings *out, const char *home, const char *mounts_path)
{
    char want[1024], cfg[1024];
    snprintf(want, sizeof want, "%s/pCloudDrive", home);
    snprintf(cfg, sizeof cfg, "%s/.pcloud", home);
    char *mounts = read_text(mounts_path);
    int mounted = 0;
    const char *line = mounts;
    while (line != NULL && *line != '\0') {
        char src[256], dst[512], fs[64];
        if (mount_line(line, src, dst, fs) && strncmp(fs, "fuse", 4) == 0
            && strcmp(dst, want) == 0)
            mounted = 1;
        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }
    free(mounts);
    if (mounted)
        add(out, "pcloud", "pcloud", GAUDIT_CLOUD_MOUNT, want, NULL);
    else if (is_dir(cfg))
        add(out, "pcloud", "pcloud", GAUDIT_CLOUD_INSTALLED, NULL, NULL);
}

/* --- Mounting at login: rclone-*.service ------------------------------------------ */

static int mounted_at(const char *mounts_path, const char *path)
{
    char *mounts = read_text(mounts_path);
    int found = 0;
    const char *line = mounts;
    while (!found && line != NULL && *line != '\0') {
        char src[256], dst[512], fs[64];
        if (mount_line(line, src, dst, fs) && strcmp(dst, path) == 0)
            found = 1;
        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }
    free(mounts);
    return found;
}

/* The remote and the mount point after "rclone mount " in a unit's
 * ExecStart=: each a bare word or in double quotes (the program writes
 * quotes around a name with spaces; systemd takes either). No escapes. */
static int unit_args(const char *at, char rem[256], char target[512])
{
    char *outs[2] = { rem, target };
    size_t lens[2] = { 256, 512 };
    for (int k = 0; k < 2; k++) {
        while (*at == ' ')
            at++;
        char end = ' ';
        if (*at == '"')
            end = '"', at++;
        size_t n = 0;
        while (*at != '\0' && *at != end) {
            if (*at == '\\' || n + 1 >= lens[k])
                return 0;
            outs[k][n++] = *at++;
        }
        if (end == '"' && *at++ != '"')
            return 0;
        outs[k][n] = '\0';
        if (n == 0)
            return 0;
    }
    return 1;
}

static void units(gaudit_cloud_findings *out, const char *home, const char *mounts_path)
{
    char dir[1024];
    snprintf(dir, sizeof dir, "%s/.config/systemd/user", home);
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && out->n_units < GAUDIT_CLOUD_MAX_UNITS) {
        size_t n = strlen(de->d_name);
        if (strncmp(de->d_name, "rclone-", 7) != 0 || n < 9 || n >= 64
            || strcmp(de->d_name + n - 8, ".service") != 0)
            continue;
        char p[1536];
        snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        char *text = read_text(p);
        char where[512] = "";
        for (char *line = text, *next; line != NULL && *line != '\0'; line = next) {
            next = strchr(line, '\n');
            if (next != NULL)
                *next++ = '\0';
            if (strncmp(line, "ExecStart=", 10) != 0)
                continue;
            char *m = strstr(line, " mount ");
            char rem[256], target[512];
            if (m != NULL && unit_args(m + 7, rem, target)) {
                if (strncmp(target, "%h/", 3) == 0)
                    snprintf(where, sizeof where, "%s%.*s", home, (int)(sizeof where - strlen(home) - 1), target + 2);
                else
                    snprintf(where, sizeof where, "%s", target);
            }
        }
        free(text);
        if (!plain_path(where))
            continue;
        gaudit_cloud_unit *u = &out->units[out->n_units++];
        snprintf(u->file, sizeof u->file, "%.63s", de->d_name);
        snprintf(u->path, sizeof u->path, "%s", where);
        snprintf(p, sizeof p, "%s/default.target.wants/%s", dir, de->d_name);
        u->enabled = exists(p);
        u->mounted = mounted_at(mounts_path, where);
    }
    closedir(d);
}

/* --- Where new cloud folders go ---------------------------------------------------- */

void gaudit_cloud_choose(const char *home, char *gathering, size_t len,
                         const gaudit_cloud_language **lang)
{
    char p[1024], locale[64] = "";
    snprintf(p, sizeof p, "%s/.config/user-dirs.locale", home != NULL ? home : "");
    char *text = home != NULL ? read_text(p) : NULL;
    if (text != NULL)
        snprintf(locale, sizeof locale, "%.*s", (int)strcspn(text, "\n"), text);
    free(text);
    const gaudit_cloud_language *l = gaudit_cloud_language_for(locale);
    if (lang != NULL)
        *lang = l;
    const char *found = NULL;
    unsigned count = 0;
    for (size_t i = 0; home != NULL && gathering_name(i) != NULL; i++) {
        snprintf(p, sizeof p, "%s/%s", home, gathering_name(i));
        if (is_dir(p))
            found = gathering_name(i), count++;
    }
    snprintf(gathering, len, "%s", count == 1 ? found : l->gathering);
}

/* --- The search ------------------------------------------------------------------- */

static int within(const char *path, const char *folder)
{
    size_t n = strlen(folder);
    return n > 0 && strncmp(path, folder, n) == 0 && path[n] == '/';
}

int gaudit_cloud_find(const gaudit_cloud_where *where, gaudit_cloud_findings *out)
{
    memset(out, 0, sizeof *out);
    if (where == NULL || where->home == NULL || where->home[0] != '/' || !is_dir(where->home))
        return -1;
    const char *home = where->home;
    const char *root = where->root != NULL ? where->root : "";
    const char *mounts = where->mounts != NULL ? where->mounts : "/proc/self/mounts";
    char p[1024];

    /* Dropbox. */
    snprintf(p, sizeof p, "%s/.dropbox/info.json", home);
    char *json = read_text(p);
    char paths[4][512];
    unsigned np = json != NULL ? gaudit_cloud_dropbox_paths(json, paths, 4) : 0;
    free(json);
    for (unsigned i = 0; i < np; i++)
        add(out, "dropbox", "dropbox", GAUDIT_CLOUD_FOLDER, paths[i], NULL);
    snprintf(p, sizeof p, "%s/usr/bin/dropbox", root);
    if (np == 0 && exists(p))
        add(out, "dropbox", "dropbox", GAUDIT_CLOUD_INSTALLED, NULL, NULL);

    /* Nextcloud (also as a Flatpak) and ownCloud. */
    static const char *const nextcloud[] = {
        "/.config/Nextcloud/nextcloud.cfg",
        "/.var/app/com.nextcloud.desktopclient.nextcloud/config/Nextcloud/nextcloud.cfg",
    };
    for (size_t i = 0; i < sizeof nextcloud / sizeof nextcloud[0]; i++) {
        snprintf(p, sizeof p, "%s%s", home, nextcloud[i]);
        qt_cfg_folders(out, p, "nextcloud");
    }
    static const char *const owncloud[] = { "/.config/ownCloud/owncloud.cfg",
                                            "/.config/ownCloud/ownCloud.cfg" };
    for (size_t i = 0; i < sizeof owncloud / sizeof owncloud[0]; i++) {
        snprintf(p, sizeof p, "%s%s", home, owncloud[i]);
        qt_cfg_folders(out, p, "owncloud");
    }

    /* MEGAsync: its settings are encrypted, so the default folders. */
    int mega = 0;
    static const char *const mega_defaults[] = { "MEGA", "MEGAsync" };
    for (size_t i = 0; i < sizeof mega_defaults / sizeof mega_defaults[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", home, mega_defaults[i]);
        if (is_dir(p)) {
            add(out, "megasync", "mega", GAUDIT_CLOUD_DEFAULT, p, NULL);
            mega = 1;
        }
    }
    char q[1024];
    snprintf(p, sizeof p, "%s/.local/share/data/Mega Limited/MEGAsync", home);
    snprintf(q, sizeof q, "%s/usr/bin/megasync", root);
    if (!mega && (is_dir(p) || exists(q)))
        add(out, "megasync", "mega", GAUDIT_CLOUD_INSTALLED, NULL, NULL);

    pcloud(out, home, mounts);

    /* Tresorit: where its folder is is not documented. */
    snprintf(p, sizeof p, "%s/.local/share/tresorit", home);
    if (is_dir(p))
        add(out, "tresorit", "tresorit", GAUDIT_CLOUD_INSTALLED, NULL, NULL);

    onedrive(out, home, root);
    insync(out, home);

    /* Jottacloud: its folder is chosen at setup, not kept where it can be read. */
    snprintf(p, sizeof p, "%s/usr/bin/jotta-cli", root);
    if (exists(p))
        add(out, "jotta-cli", "jottacloud", GAUDIT_CLOUD_INSTALLED, NULL, NULL);

    rclone(out, home, mounts);
    units(out, home, mounts);

    /* The gathering folder, and what is under it. */
    for (size_t i = 0; gathering_name(i) != NULL; i++) {
        snprintf(p, sizeof p, "%s/%s", home, gathering_name(i));
        if (is_dir(p)) {
            out->gathering_count++;
            if (out->gathering[0] == '\0')
                snprintf(out->gathering, sizeof out->gathering, "%.511s", p);
        }
    }
    for (unsigned i = 0; i < out->n; i++) {
        for (size_t g = 0; gathering_name(g) != NULL; g++) {
            snprintf(p, sizeof p, "%s/%s", home, gathering_name(g));
            if (out->f[i].path[0] != '\0' && within(out->f[i].path, p))
                out->f[i].gathered = 1;
        }
    }
    return 0;
}
