/* SPDX-License-Identifier: GPL-3.0-only */
/* The public share folder: user-dirs.dirs read strictly, a .mo catalog
 * read strictly, and on a home folder the test builds (never the real
 * one) the standard folder and every other folder with a name it could
 * have had: from the project's table, from a catalog on the machine, the
 * system's default, a link, a name in another case. */
#define _GNU_SOURCE
#include "public-share.h"

#include <stdint.h>
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

static void put(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f != NULL) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

static void le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

/* A little-endian .mo with the given pairs, sorted as given. */
static size_t make_mo(unsigned char *buf, const char *const *pairs, uint32_t n)
{
    uint32_t orig = 28, trans = orig + 8 * n, strings = trans + 8 * n;
    memset(buf, 0, strings);
    le32(buf, 0x950412de);
    le32(buf + 8, n);
    le32(buf + 12, orig);
    le32(buf + 16, trans);
    uint32_t at = strings;
    for (uint32_t t = 0; t < 2; t++)
        for (uint32_t i = 0; i < n; i++) {
            const char *s = pairs[2 * i + t];
            uint32_t l = (uint32_t)strlen(s);
            le32(buf + (t ? trans : orig) + 8 * i, l);
            le32(buf + (t ? trans : orig) + 8 * i + 4, at);
            memcpy(buf + at, s, l + 1);
            at += l + 1;
        }
    return at;
}

static const gaudit_public_folder *found(const gaudit_public_share *s, const char *name)
{
    for (unsigned i = 0; i < s->n_found; i++)
        if (strcmp(s->found[i].name, name) == 0)
            return &s->found[i];
    return NULL;
}

int main(void)
{
    /* user-dirs.dirs as xdg-user-dirs writes it, and nothing else. */
    char out[512];
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/Offentlig\"\n", "/home/u", out,
                                        sizeof out) == GAUDIT_PUBLIC_CONFIG_SET
          && strcmp(out, "/home/u/Offentlig") == 0);
    CHECK(gaudit_public_parse_user_dirs("# c\nXDG_PUBLICSHARE_DIR=\"/srv/share/\"\n", "/home/u", out,
                                        sizeof out) == GAUDIT_PUBLIC_CONFIG_SET
          && strcmp(out, "/srv/share") == 0);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/My \\\"Share\\\"\"\n", "/home/u",
                                        out, sizeof out) == GAUDIT_PUBLIC_CONFIG_SET
          && strcmp(out, "/home/u/My \"Share\"") == 0);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_DISABLED);
    CHECK(gaudit_public_parse_user_dirs("XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_NONE);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$XDG_X/a\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_UNKNOWN);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$(id)\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_UNKNOWN);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"relative\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_UNKNOWN);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/a\" ; rm\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_UNKNOWN);
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/../x\"\n", "/home/u", out, sizeof out)
          == GAUDIT_PUBLIC_CONFIG_UNKNOWN);
    /* The last definition counts. */
    CHECK(gaudit_public_parse_user_dirs("XDG_PUBLICSHARE_DIR=\"$HOME/A\"\nXDG_PUBLICSHARE_DIR=\"$HOME/B\"\n",
                                        "/home/u", out, sizeof out) == GAUDIT_PUBLIC_CONFIG_SET
          && strcmp(out, "/home/u/B") == 0);

    /* A catalog: found, absent, damaged. */
    unsigned char mo[1024];
    const char *pairs[] = { "", "Content-Type: text/plain; charset=UTF-8\n", "Desktop", "Skrivebord",
                            "Public", "Allmenn" };
    size_t mlen = make_mo(mo, pairs, 3);
    char name[256];
    CHECK(gaudit_mo_lookup(mo, mlen, "Public", name, sizeof name) == 0 && strcmp(name, "Allmenn") == 0);
    CHECK(gaudit_mo_lookup(mo, mlen, "Music", name, sizeof name) == -1);
    CHECK(gaudit_mo_lookup(mo, 20, "Public", name, sizeof name) == -1);
    unsigned char bad[1024];
    memcpy(bad, mo, mlen);
    le32(bad + 28 + 8 * 2 + 4, 100000);  /* "Public" pointing outside the file */
    CHECK(gaudit_mo_lookup(bad, mlen, "Public", name, sizeof name) == -1);

    /* A home folder of the test's own. */
    char dir[] = "/tmp/gaudit-public-XXXXXX";
    if (mkdtemp(dir) == NULL)
        return 1;
    char p[2200];
    const char *folders[] = { "Offentlig", "Public", "Delat", "PUBLIKT", "Allmenn", "Documents", "Standard" };
    for (size_t i = 0; i < sizeof folders / sizeof folders[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, folders[i]);
        mkdir(p, 0755);
    }
    snprintf(p, sizeof p, "%s/Offentleg", dir);
    CHECK(symlink("Offentlig", p) == 0);
    snprintf(p, sizeof p, "%s/.config", dir);
    mkdir(p, 0700);
    char dirs_file[1024], locale_file[1024], defaults[1024], locales[1024];
    snprintf(dirs_file, sizeof dirs_file, "%s/.config/user-dirs.dirs", dir);
    snprintf(locale_file, sizeof locale_file, "%s/.config/user-dirs.locale", dir);
    snprintf(defaults, sizeof defaults, "%s/user-dirs.defaults", dir);
    const char *d1 = "XDG_DESKTOP_DIR=\"$HOME/Skrivebord\"\nXDG_PUBLICSHARE_DIR=\"$HOME/Offentlig\"\n";
    put(dirs_file, d1, strlen(d1));
    put(locale_file, "nb_NO\n", 6);
    const char *d2 = "DESKTOP=Desktop\nPUBLICSHARE=Standard\n";
    put(defaults, d2, strlen(d2));
    snprintf(locales, sizeof locales, "%s/locale", dir);
    mkdir(locales, 0755);
    snprintf(p, sizeof p, "%s/xx", locales);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/xx/LC_MESSAGES", locales);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/xx/LC_MESSAGES/xdg-user-dirs.mo", locales);
    put(p, mo, mlen);

    const char *ld[] = { locales, NULL };
    gaudit_public_where w = { .home = dir, .user_dirs = dirs_file, .user_locale = locale_file,
                              .system_defaults = defaults, .locale_dirs = ld };
    gaudit_public_share s;
    CHECK(gaudit_public_share_find(&w, &s) == 0);
    CHECK(s.config == GAUDIT_PUBLIC_CONFIG_SET && s.standard_exists);
    CHECK(strcmp(s.locale, "nb_NO") == 0 && strcmp(s.system_default, "Standard") == 0);
    const gaudit_public_folder *f;
    CHECK((f = found(&s, "Offentlig")) != NULL && f->is_standard && strcmp(f->lang, "nb") == 0);
    CHECK((f = found(&s, "Public")) != NULL && !f->is_standard);
    CHECK((f = found(&s, "Delat")) != NULL && !f->current_name && strcmp(f->lang, "sv") == 0);
    CHECK((f = found(&s, "PUBLIKT")) != NULL && f->case_differs);
    CHECK((f = found(&s, "Allmenn")) != NULL && f->from_machine && strcmp(f->lang, "xx") == 0);
    CHECK((f = found(&s, "Standard")) != NULL);          /* the system's own default */
    CHECK((f = found(&s, "Offentleg")) != NULL && f->symlink && strcmp(f->link_target, "Offentlig") == 0);
    CHECK(found(&s, "Documents") == NULL);
    CHECK(s.n_found == 7 && !s.more);

    /* Switched off, and no settings at all. */
    const char *d3 = "XDG_PUBLICSHARE_DIR=\"$HOME/\"\n";
    put(dirs_file, d3, strlen(d3));
    CHECK(gaudit_public_share_find(&w, &s) == 0 && s.config == GAUDIT_PUBLIC_CONFIG_DISABLED
          && found(&s, "Offentlig") != NULL && !found(&s, "Offentlig")->is_standard);
    unlink(dirs_file);
    CHECK(gaudit_public_share_find(&w, &s) == 0 && s.config == GAUDIT_PUBLIC_CONFIG_NONE);

    /* Tidying up: Public into Offentlig, never overwriting; a folder only
     * removed when empty; never through a link. */
    char q[2200];
    snprintf(q, sizeof q, "%s/Offentlig/a.txt", dir);
    put(q, "in use", 6);
    snprintf(q, sizeof q, "%s/Public/a.txt", dir);
    put(q, "other", 5);
    snprintf(q, sizeof q, "%s/Public/b.txt", dir);
    put(q, "b", 1);
    snprintf(q, sizeof q, "%s/Public/sub", dir);
    mkdir(q, 0755);
    gaudit_public_merge_result r;
    /* Checked first: a.txt is in both, b.txt and sub could go. */
    CHECK(gaudit_public_merge_check(dir, "Public", "Offentlig", &r) == 1 && r.moved == 2
          && r.clashes == 1 && strcmp(r.clash[0], "a.txt") == 0);
    /* With a clash, nothing moves at all: never half a merge. */
    CHECK(gaudit_public_merge(dir, "Public", "Offentlig", &r) == 1 && r.moved == 0 && r.clashes == 1);
    snprintf(q, sizeof q, "%s/Public/b.txt", dir);
    struct stat sb;
    CHECK(stat(q, &sb) == 0);  /* still where it was */
    /* The user renames the clash themselves; then everything goes. */
    char renamed[2200];
    snprintf(q, sizeof q, "%s/Public/a.txt", dir);
    snprintf(renamed, sizeof renamed, "%s/Public/a (from Public).txt", dir);
    CHECK(rename(q, renamed) == 0);
    CHECK(gaudit_public_merge_check(dir, "Public", "Offentlig", &r) == 0 && r.moved == 3);
    CHECK(gaudit_public_merge(dir, "Public", "Offentlig", &r) == 0 && r.moved == 3);
    snprintf(q, sizeof q, "%s/Offentlig/a.txt", dir);
    FILE *kept = fopen(q, "r");
    char what[16] = "";
    if (kept != NULL) {
        if (fgets(what, sizeof what, kept) == NULL)
            what[0] = '\0';
        fclose(kept);
    }
    CHECK(strcmp(what, "in use") == 0);  /* not replaced */
    snprintf(q, sizeof q, "%s/Offentlig/sub", dir);
    CHECK(stat(q, &sb) == 0 && S_ISDIR(sb.st_mode));
    snprintf(q, sizeof q, "%s/Public/keep", dir);
    put(q, "k", 1);
    CHECK(gaudit_public_remove_empty(dir, "Public") == 1);  /* not empty: left as it is */
    unlink(q);  /* the user's own choice, never the program's */
    CHECK(gaudit_public_remove_empty(dir, "Public") == 0);
    snprintf(q, sizeof q, "%s/Public", dir);
    CHECK(stat(q, &sb) != 0);
    /* Refused: a link, the same folder, a path, a folder that is not there. */
    CHECK(gaudit_public_merge(dir, "Offentleg", "Offentlig", &r) == -1);
    CHECK(gaudit_public_remove_empty(dir, "Offentleg") == -1);
    CHECK(gaudit_public_merge(dir, "Offentlig", "Offentlig", &r) == -1);
    CHECK(gaudit_public_merge(dir, "../x", "Offentlig", &r) == -1);
    CHECK(gaudit_public_remove_empty(dir, "Delat/..") == -1);
    CHECK(gaudit_public_remove_empty(dir, "Nowhere") == -1);
    CHECK(gaudit_public_remove_empty(dir, "Delat") == 0);  /* empty: removed */

    char cmd[1200];
    snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", dir);
    if (system(cmd) != 0)
        failures++;
    if (failures == 0)
        puts("public-share: all checks passed");
    return failures == 0 ? 0 : 1;
}
