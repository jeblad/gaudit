/* SPDX-License-Identifier: GPL-3.0-only */
#include "shared-mode.h"

#include "probe-quote.h"
#include "public-share.h"
#include "shared-folder.h"

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int emit(FILE *out, int r, const char *buf)
{
    return r == 0 && fputs(buf, out) >= 0 ? 0 : -1;
}

/* The standard folder as shown: "~/name" in the home folder, else absolute. */
static void shown_standard(const char *home, const char *standard, char *out, size_t len)
{
    size_t hl = strlen(home);
    if (strncmp(standard, home, hl) == 0 && standard[hl] == '/')
        snprintf(out, len, "~%s", standard + hl);
    else
        snprintf(out, len, "%s", standard);
}

int gaudit_shared_collect(const char *home, unsigned uid, const char *const *locale_dirs,
                          const char *smb_conf, const char *proc, FILE *out)
{
    gaudit_public_where w = { .home = home, .locale_dirs = locale_dirs };
    gaudit_public_share s;
    if (gaudit_public_share_find(&w, &s) != 0)
        return 1;
    char buf[2048];
    gaudit_shared_config c = { .state = (int)s.config, .exists = s.standard_exists, .names = s.names };
    if (s.config == GAUDIT_PUBLIC_CONFIG_SET) {
        shown_standard(home, s.standard, c.standard, sizeof c.standard);
        if (strlen(s.standard) >= sizeof c.standard - 1)
            c.state = GAUDIT_PUBLIC_CONFIG_UNKNOWN;  /* too long to send: not guessed at */
    }
    snprintf(c.locale, sizeof c.locale, "%s", s.locale);
    snprintf(c.default_name, sizeof c.default_name, "%.127s", s.system_default);
    if (emit(out, gaudit_shared_format_config(&c, buf, sizeof buf), buf) != 0)
        return 1;
    unsigned folders = 0;
    for (unsigned i = 0; i < s.n_found; i++) {
        const gaudit_public_folder *p = &s.found[i];
        gaudit_shared_folder f = { .machine = p->from_machine, .current = p->current_name,
                                   .standard = p->is_standard, .link = p->symlink,
                                   .case_differs = p->case_differs, .entries = p->entries };
        snprintf(f.name, sizeof f.name, "%s", p->name);
        snprintf(f.lang, sizeof f.lang, "%s", p->lang);
        snprintf(f.target, sizeof f.target, "%.255s", p->link_target);
        if (gaudit_shared_format_folder(&f, buf, sizeof buf) == 0 && fputs(buf, out) >= 0)
            folders++;
    }
    gaudit_share_where sw = { .home = home, .smb_conf = smb_conf, .proc = proc, .uid = uid,
                              .publicshare = s.config == GAUDIT_PUBLIC_CONFIG_SET ? s.standard : NULL };
    gaudit_share_services sv;
    gaudit_share_services_find(&sw, &sv);
    static const char *const kinds[] = { "samba", "samba-user", "gnome" };
    unsigned services = 0;
    for (unsigned i = 0; i < sv.n; i++) {
        gaudit_shared_service o = { 0 };
        snprintf(o.kind, sizeof o.kind, "%s", kinds[sv.s[i].kind]);
        snprintf(o.name, sizeof o.name, "%s", sv.s[i].name);
        snprintf(o.path, sizeof o.path, "%.255s", sv.s[i].path);
        if (gaudit_shared_format_service(&o, buf, sizeof buf) == 0 && fputs(buf, out) >= 0)
            services++;
    }
    gaudit_shared_end e = { .folders = folders, .services = services, .more = s.more || sv.more,
                            .usershares = sv.usershares_unreadable };
    if (emit(out, gaudit_shared_format_end(&e, buf, sizeof buf), buf) != 0)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* --- Tidying ------------------------------------------------------------------ */

/* Whether a service shares folder, or a folder above it (Samba's [homes]
 * shares the whole home folder). */
static int shared_by_service(const gaudit_share_services *sv, const char *folder)
{
    for (unsigned i = 0; i < sv->n; i++)
        if (gaudit_path_within(folder, sv->s[i].path) || gaudit_path_within(sv->s[i].path, folder))
            return 1;
    return 0;
}

/* The tidying only works on what the collection itself finds: <to> must be
 * the folder user-dirs.dirs names, straight in the home folder, and <from>
 * (or <name>) one of the other folders with a name it could have had,
 * not a link; and no service may share either. */
static int allowed(const char *home, unsigned uid, const char *from, const char *to)
{
    gaudit_public_where w = { .home = home };
    gaudit_public_share s;
    if (gaudit_public_share_find(&w, &s) != 0)
        return 0;
    int from_ok = 0, to_ok = to == NULL;
    for (unsigned i = 0; i < s.n_found; i++) {
        const gaudit_public_folder *f = &s.found[i];
        if (f->symlink)
            continue;
        if (!f->is_standard && strcmp(f->name, from) == 0)
            from_ok = 1;
        if (to != NULL && f->is_standard && strcmp(f->name, to) == 0)
            to_ok = 1;
    }
    if (!from_ok || !to_ok)
        return 0;
    gaudit_share_where sw = { .home = home, .uid = uid,
                              .publicshare = s.config == GAUDIT_PUBLIC_CONFIG_SET ? s.standard : NULL };
    gaudit_share_services sv;
    gaudit_share_services_find(&sw, &sv);
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", home, from);
    if (shared_by_service(&sv, path))
        return 0;
    if (to != NULL) {
        snprintf(path, sizeof path, "%s/%s", home, to);
        if (shared_by_service(&sv, path))
            return 0;
    }
    return 1;
}

static int report_moves(int result, const gaudit_public_merge_result *r)
{
    for (unsigned i = 0; i < r->clashes && i < GAUDIT_PUBLIC_MAX_CLASHES; i++) {
        char name[sizeof r->clash[0] * 2 + 3];
        if (gaudit_probe_quote(name, sizeof name, r->clash[i]) == 0)
            printf("(shared-clash (name %s))\n", name);
    }
    printf("(shared-moves (result %d) (moved %u) (clashes %u) (other-disk %u) (failed %u))\n",
           result, r->moved, r->clashes, r->other_disk, r->failed);
    return fflush(stdout) == 0 ? 0 : 1;
}

int gaudit_shared_mode(int argc, char *argv[])
{
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/')
        return 1;
    const char *home = pw->pw_dir;
    if (argc == 3 && (strcmp(argv[2], "quick") == 0 || strcmp(argv[2], "full") == 0))
        return gaudit_shared_collect(home, (unsigned)getuid(), NULL, NULL, NULL, stdout);
    if (argc == 5 && (strcmp(argv[2], "check") == 0 || strcmp(argv[2], "merge") == 0)) {
        gaudit_public_merge_result r = { 0 };
        if (!allowed(home, (unsigned)getuid(), argv[3], argv[4]))
            return report_moves(2, &r);
        int res = strcmp(argv[2], "check") == 0 ? gaudit_public_merge_check(home, argv[3], argv[4], &r)
                                                : gaudit_public_merge(home, argv[3], argv[4], &r);
        return report_moves(res < 0 ? 2 : res, &r);
    }
    if (argc == 4 && strcmp(argv[2], "remove") == 0) {
        int res = allowed(home, (unsigned)getuid(), argv[3], NULL)
                      ? gaudit_public_remove_empty(home, argv[3]) : -1;
        printf("(shared-removed (result %d))\n", res < 0 ? 2 : res);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    return 2;
}
