/* SPDX-License-Identifier: GPL-3.0-only */
/* Cloud folders, on a home folder the test builds (never the real one),
 * each client's files as its documentation describes them: Dropbox's
 * info.json, Nextcloud's .cfg (also the Flatpak's), the onedrive client's
 * config, Insync's folders, rclone's remotes (names and types only, a
 * crypt over one, a mount), pCloud's mount, MEGAsync's default folder,
 * Tresorit and jotta-cli installed, and the gathering folder. */
#define _GNU_SOURCE
#include "cloud-folders.h"

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

static char dir[] = "/tmp/gaudit-cloud-XXXXXX";

static void mk(const char *rel)
{
    char p[2048];
    snprintf(p, sizeof p, "mkdir -p -- '%s/%s'", dir, rel);
    if (system(p) != 0)
        failures++;
}

static void put(const char *rel, const char *text)
{
    char p[2048];
    snprintf(p, sizeof p, "%s/%s", dir, rel);
    FILE *f = fopen(p, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

static const gaudit_cloud_finding *find(const gaudit_cloud_findings *s, const char *client,
                                        const char *service)
{
    for (unsigned i = 0; i < s->n; i++)
        if (strcmp(s->f[i].client, client) == 0 && strcmp(s->f[i].service, service) == 0)
            return &s->f[i];
    return NULL;
}

int main(void)
{
    /* info.json: two accounts, an escape, and one not taken (\u). */
    char out[4][512];
    CHECK(gaudit_cloud_dropbox_paths("{\"personal\": {\"path\": \"/home/u/Dropbox\", \"host\": 1},"
                                     " \"business\": {\"path\": \"/home/u/Dropbox (Firma)\"}}",
                                     out, 4) == 2
          && strcmp(out[1], "/home/u/Dropbox (Firma)") == 0);
    CHECK(gaudit_cloud_dropbox_paths("{\"personal\": {\"path\": \"/home/u/\\u0044ropbox\"}}", out, 4) == 0);
    CHECK(gaudit_cloud_dropbox_paths("{\"personal\": {\"path\": \"relative\"}}", out, 4) == 0);

    if (mkdtemp(dir) == NULL)
        return 1;
    char home[1024], root[1024], mounts[1024], text[4096];
    snprintf(home, sizeof home, "%s/home", dir);
    snprintf(root, sizeof root, "%s/root", dir);
    snprintf(mounts, sizeof mounts, "%s/mounts", dir);
    mk("home/.dropbox");
    mk("home/Cloud/Dropbox");
    snprintf(text, sizeof text, "{\"personal\": {\"path\": \"%s/Cloud/Dropbox\"}}", home);
    put("home/.dropbox/info.json", text);
    mk("home/.var/app/com.nextcloud.desktopclient.nextcloud/config/Nextcloud");
    snprintf(text, sizeof text, "[Accounts]\n0\\Folders\\1\\localPath=%s/Nextcloud/\n"
                                "0\\Folders\\1\\paused=false\n", home);
    put("home/.var/app/com.nextcloud.desktopclient.nextcloud/config/Nextcloud/nextcloud.cfg", text);
    mk("home/.config/onedrive");
    put("home/.config/onedrive/config", "# sync_dir = \"~/Old\"\nsync_dir = \"~/OneDrive Jobb\"\n");
    mk("home/Insync/me@example.com/Google Drive");
    mk("home/MEGA");
    mk("home/.local/share/tresorit");
    mk("home/.config/rclone");
    put("home/.config/rclone/rclone.conf",
        "[gdrive]\ntype = drive\ntoken = {\"access_token\":\"SECRET\"}\n\n"
        "[secret]\ntype = crypt\nremote = gdrive:vault\npassword = XXXX\n\n"
        "[backup]\ntype = s3\nsecret_access_key = YYY\n\n"
        "[jotta]\ntype = jottacloud\n");
    mk("home/pCloudDrive");
    snprintf(text, sizeof text,
             "/dev/sda1 / ext4 rw 0 0\n"
             "pCloud.fs %s/pCloudDrive fuse.pCloud.fs rw 0 0\n"
             "jotta: %s/Cloud/Jotta fuse.rclone rw 0 0\n"
             "secret: %s/Cloud/Google fuse.rclone rw 0 0\n", home, home, home);
    put("mounts", text);
    mk("root/usr/bin");
    put("root/usr/bin/jotta-cli", "");

    gaudit_cloud_where w = { .home = home, .mounts = mounts, .root = root };
    gaudit_cloud_findings s;
    CHECK(gaudit_cloud_find(&w, &s) == 0);
    const gaudit_cloud_finding *f;
    char want[1200];
    snprintf(want, sizeof want, "%s/Cloud/Dropbox", home);
    CHECK((f = find(&s, "dropbox", "dropbox")) != NULL && f->how == GAUDIT_CLOUD_FOLDER
          && strcmp(f->path, want) == 0 && f->gathered);
    snprintf(want, sizeof want, "%s/Nextcloud", home);
    CHECK((f = find(&s, "nextcloud", "nextcloud")) != NULL && strcmp(f->path, want) == 0 && !f->gathered);
    snprintf(want, sizeof want, "%s/OneDrive Jobb", home);
    CHECK((f = find(&s, "onedrive", "onedrive")) != NULL && strcmp(f->path, want) == 0);
    CHECK((f = find(&s, "insync", "google-drive")) != NULL && strcmp(f->name, "me@example.com") == 0);
    CHECK((f = find(&s, "megasync", "mega")) != NULL && f->how == GAUDIT_CLOUD_DEFAULT);
    CHECK((f = find(&s, "tresorit", "tresorit")) != NULL && f->how == GAUDIT_CLOUD_INSTALLED);
    CHECK((f = find(&s, "pcloud", "pcloud")) != NULL && f->how == GAUDIT_CLOUD_MOUNT);
    /* rclone: drive covered by the crypt, and mounted through it; s3 left
     * out; jottacloud mounted itself. */
    snprintf(want, sizeof want, "%s/Cloud/Google", home);
    CHECK((f = find(&s, "rclone", "google-drive")) != NULL && f->how == GAUDIT_CLOUD_MOUNT
          && strcmp(f->path, want) == 0 && f->encrypted && strcmp(f->name, "gdrive") == 0
          && strcmp(f->via, "secret") == 0);
    CHECK((f = find(&s, "rclone", "jottacloud")) != NULL && f->how == GAUDIT_CLOUD_MOUNT && f->gathered
          && !f->encrypted && f->via[0] == '\0');
    for (unsigned i = 0; i < s.n; i++)
        CHECK(strstr(s.f[i].name, "SECRET") == NULL && strstr(s.f[i].path, "SECRET") == NULL);
    CHECK(find(&s, "jotta-cli", "jottacloud") != NULL);
    CHECK(s.gathering_count == 1 && s.gathering[0] != '\0' && !s.rclone_unreadable);
    unsigned rclone_found = 0;
    for (unsigned i = 0; i < s.n; i++)
        rclone_found += strcmp(s.f[i].client, "rclone") == 0;
    CHECK(rclone_found == 2);  /* not the s3 remote, not the crypt itself */

    /* An encrypted rclone file: nothing read, said so. A second gathering
     * folder: counted. */
    put("home/.config/rclone/rclone.conf", "# Encrypted rclone configuration File\n\nRCLONE_ENCRYPT_V0:\nabc\n");
    mk("home/SkyTjenester");
    CHECK(gaudit_cloud_find(&w, &s) == 0 && s.rclone_unreadable && s.gathering_count == 2
          && find(&s, "rclone", "google-drive") == NULL);

    char cmd[1200];
    snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", dir);
    if (system(cmd) != 0)
        failures++;
    if (failures == 0)
        puts("cloud-folders: all checks passed");
    return failures == 0 ? 0 : 1;
}
