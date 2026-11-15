/* SPDX-License-Identifier: GPL-3.0-only */
/* "gaudit-orchestrator secrets quick|full [folder ...]": the plugin's
 * collection, as the user. quick: the known locations only (fast, for
 * Home). full: the same known locations first, then the deep scan of the
 * whole home directory, and of each folder the user added (its whole tree,
 * within its filesystem); a path is reported once. So the full collection
 * always holds everything the quick one finds: a deeper level adds to the
 * collection, it does not replace it, and only the presentation differs.
 * Reports path, reason, mode and reach, never any content. Those others
 * can reach come first, so they are always among the findings sent. */
#include "secrets-mode.h"

#include "private-files.h"
#include "secret-scan.h"
#include "secrets.h"
#include "probe-quote.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

/* Findings kept for sorting; beyond this they are counted only. */
#define MAX_KEPT 4096

typedef struct {
    const struct passwd *me;
    int own_gid_private;          /* the user's primary group is their own private group */
    char home[4096];
    unsigned area;                /* the area being searched */
    gaudit_secret_finding *kept;
    unsigned n_kept;
    gaudit_secrets_summary sum;
} scan_state;

/* The user's own private group: same name as the user and their primary
 * group, with no other members (as Ubuntu creates them). */
static int own_private_group(const struct passwd *me)
{
    struct group *gr = getgrgid(me->pw_gid);
    if (gr == NULL || strcmp(gr->gr_name, me->pw_name) != 0)
        return 0;
    for (char **m = gr->gr_mem; *m != NULL; m++)
        if (strcmp(*m, me->pw_name) != 0)
            return 0;
    return 1;
}

/* Whether text goes through the protocol unchanged (no byte replaced). */
static int sent_as_is(const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

/* Counts a finding and keeps it for sending. */
static void add(scan_state *st, const char *rel, const char *reason, unsigned mode,
                gaudit_secret_reach reach, int owned)
{
    st->sum.count++;
    if (reach == GAUDIT_SECRET_OTHERS)
        st->sum.others++;
    else if (reach == GAUDIT_SECRET_GROUP)
        st->sum.groups++;
    if (st->n_kept >= MAX_KEPT)
        return;
    gaudit_secret_finding *f = &st->kept[st->n_kept];
    memset(f, 0, sizeof *f);
    /* Too long to send: counted, not listed. */
    if (snprintf(f->path, sizeof f->path, "%s", rel[0] != '\0' ? rel : ".") >= (int)sizeof f->path
        || snprintf(f->reason, sizeof f->reason, "%s", reason) >= (int)sizeof f->reason)
        return;
    f->area = st->area;
    f->mode = mode & 07777;
    f->reach = reach;
    f->owned = owned;
    f->exact = sent_as_is(rel);
    st->n_kept++;
}

/* Whether rel was reported already (by the known locations). */
static int already(const scan_state *st, const char *rel)
{
    for (unsigned i = 0; i < st->n_kept; i++)
        if (st->kept[i].area == st->area && strcmp(st->kept[i].path, rel) == 0)
            return 1;
    return 0;
}

/* A problem in a known location: the same rules as Home's count. */
static void on_known(const char *rel, gaudit_private_rule rule, void *ctx)
{
    scan_state *st = ctx;
    static const char *const reasons[] = {
        [GAUDIT_PRIVATE_HOME_WRITABLE] = "home-writable",
        [GAUDIT_PRIVATE_TOOL_MODE] = "tool-mode",
        [GAUDIT_PRIVATE_REACH] = "known-secret",
    };
    char path[8192];
    struct stat sb;
    unsigned mode = 0;
    int owned = 0;
    if (snprintf(path, sizeof path, "%s/%s", st->home, rel) < (int)sizeof path && stat(path, &sb) == 0) {
        mode = (unsigned)(sb.st_mode & 07777);
        owned = sb.st_uid == st->me->pw_uid;
    }
    /* Others' bits open: every account; otherwise a group (simplified
     * where the folders on the way differ, as Home's rule is). */
    gaudit_secret_reach reach = (mode & 0007) != 0 || !owned ? GAUDIT_SECRET_OTHERS : GAUDIT_SECRET_GROUP;
    add(st, rel, reasons[rule], mode, reach, owned);
}

static void on_hit(const gaudit_secret_hit *hit, void *ctx)
{
    scan_state *st = ctx;
    if (already(st, hit->rel))
        return;  /* the known locations have judged it */
    gaudit_secret_reach reach = GAUDIT_SECRET_OWNER;
    if (hit->reach == GAUDIT_REACH_OTHERS)
        reach = GAUDIT_SECRET_OTHERS;
    else if (hit->reach == GAUDIT_REACH_GROUP)
        reach = st->own_gid_private && hit->gid == st->me->pw_gid ? GAUDIT_SECRET_OWN_GROUP
                                                                  : GAUDIT_SECRET_GROUP;
    add(st, hit->rel, hit->reason, (unsigned)hit->mode, reach, hit->owned);
}

/* Wider reach first; then by path, so the order is stable. */
static int by_reach(const void *a, const void *b)
{
    const gaudit_secret_finding *x = a, *y = b;
    if (x->reach != y->reach)
        return (int)y->reach - (int)x->reach;
    return strcmp(x->path, y->path);
}

/* Network filesystems: modes and owners there may not say who can reach a
 * file on the server. */
static int remote_fs(const char *path)
{
    struct statfs sf;
    if (statfs(path, &sf) != 0)
        return 0;
    switch ((unsigned long)sf.f_type) {
    case 0x6969UL:       /* NFS */
    case 0x517BUL:       /* SMB */
    case 0xFF534D42UL:   /* CIFS */
    case 0xFE534D42UL:   /* SMB2 */
    case 0x65735546UL:   /* FUSE (sshfs, rclone, gvfs and others) */
    case 0x01021997UL:   /* 9P */
    case 0x00C36400UL:   /* Ceph */
    case 0x5346414FUL:   /* AFS */
    case 0x73757245UL:   /* Coda */
        return 1;
    default:
        return 0;
    }
}

/* Whether a is b or lies inside it. */
static int within(const char *a, const char *b)
{
    size_t n = strlen(b);
    return strncmp(a, b, n) == 0 && (a[n] == '\0' || a[n] == '/' || (n == 1 && b[0] == '/'));
}

static int emit_area(FILE *out, unsigned index, const char *path, gaudit_area_status status)
{
    gaudit_secret_area a = { .index = index, .status = status, .exact = sent_as_is(path) };
    if (snprintf(a.path, sizeof a.path, "%s", path) >= (int)sizeof a.path) {
        /* Named cut short (only an unreadable one, or a very long home). */
        a.path[sizeof a.path - 2] = '/';
        a.path[sizeof a.path - 1] = '\0';
        a.exact = 0;
    }
    a.remote = status == GAUDIT_AREA_SEARCHED && remote_fs(path);
    char line[1200];
    return gaudit_secrets_format_area(&a, line, sizeof line) == 0 && fputs(line, out) != EOF ? 0 : -1;
}

/* Progress: "(progress (count N) (where "..."))", entries looked at so
 * far and the folder being searched ("~" for the home folder), at most
 * every two seconds, so the GUI can show the search is alive and where it
 * is slow. Not part of the collection. */
typedef struct {
    FILE *out;
    unsigned long done;      /* entries in the areas finished */
    struct timespec last_time;
    char root[300];          /* the area's root as shown: "~" or a path */
    char last[PATH_MAX];     /* the folder at the last report, under root */
} progress_state;

/* A new area: its root, shown as it is reported. */
static void progress_where(progress_state *p, const char *root)
{
    snprintf(p->root, sizeof p->root, "%s", root);
    p->last[0] = '\0';
}

/* The stem two reports share: the longest run of whole folder names that
 * the folder now and the folder two seconds ago have in common. A search
 * that stays in one tree narrows to it; one moving quickly shows a higher
 * level. Roughly where it is, not exactly. */
static void common_stem(char *last, const char *now)
{
    size_t i = 0, cut = 0;
    while (last[i] != '\0' && last[i] == now[i]) {
        i++;
        if (last[i] == '/' || last[i] == '\0')
            cut = (now[i] == '/' || now[i] == '\0') ? i : cut;
    }
    last[cut] = '\0';
}

/* After an area's search: how it went. */
static int emit_stats(FILE *out, unsigned index, const gaudit_secret_stats *s,
                      const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    gaudit_secret_area_stats a = { .index = index, .entries = (unsigned long)s->dirs + s->files,
                                   .seconds = (unsigned)(now.tv_sec - start->tv_sec),
                                   .truncated = s->truncated, .caches = s->caches };
    char line[256];
    return gaudit_secrets_format_area_stats(&a, line, sizeof line) == 0 && fputs(line, out) != EOF
           ? 0 : -1;
}

static void on_progress(unsigned long entries, const char *rel, void *ctx)
{
    progress_state *p = ctx;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - p->last_time.tv_sec < 2)
        return;
    p->last_time = now;
    /* Where it was then, narrowed to what it shares with where it is now. */
    char stem[PATH_MAX];
    snprintf(stem, sizeof stem, "%s", p->last);
    if (p->last[0] != '\0')
        common_stem(stem, rel);
    else
        snprintf(stem, sizeof stem, "%s", rel);
    snprintf(p->last, sizeof p->last, "%s", rel);
    char where[PATH_MAX + 320], quoted[2 * (PATH_MAX + 320)];
    snprintf(where, sizeof where, "%s%s%s", p->root, stem[0] != '\0' ? "/" : "", stem);
    if (strlen(where) > 240)  /* fits the protocol's text field */
        where[240] = '\0';
    if (gaudit_probe_quote(quoted, sizeof quoted, where) != 0)
        snprintf(quoted, sizeof quoted, "\"?\"");
    fprintf(p->out, "(progress (count %lu) (where %s))\n", p->done + entries, quoted);
    fflush(p->out);
}

int gaudit_private_files_collect(const struct passwd *pw, int deep, const char *const *folders,
                                 size_t n_folders, FILE *out)
{
    progress_state progress = { .out = out };
    clock_gettime(CLOCK_MONOTONIC, &progress.last_time);
    progress_where(&progress, "~");
    if (deep)
        fprintf(out, "(read-limit (bytes %zu))\n", gaudit_secret_scan_read_limit());
    gaudit_secret_scan_set_progress(on_progress, &progress);
    scan_state st = { 0 };
    st.sum.status = GAUDIT_SECRETS_UNKNOWN;
    st.kept = calloc(MAX_KEPT, sizeof *st.kept);
    if (pw != NULL && pw->pw_dir != NULL && st.kept != NULL) {
        st.me = pw;
        st.own_gid_private = own_private_group(pw);
        snprintf(st.home, sizeof st.home, "%s", pw->pw_dir);
        gaudit_secret_stats stats;
        gid_t own_gid = st.own_gid_private ? pw->pw_gid : (gid_t)-1;
        memset(&stats, 0, sizeof stats);
        if (emit_area(out, 0, pw->pw_dir, GAUDIT_AREA_SEARCHED) != 0) {
            free(st.kept);
            gaudit_secret_scan_set_progress(NULL, NULL);
            return 1;
        }
        struct timespec started;
        clock_gettime(CLOCK_MONOTONIC, &started);
        if (gaudit_private_files_each(pw->pw_dir, getuid(), own_gid, on_known, &st) >= 0
            && (!deep || gaudit_secret_scan(pw->pw_dir, getuid(), on_hit, &st, &stats) == 0)) {
            st.sum.status = GAUDIT_SECRETS_OK;
            st.sum.truncated = stats.truncated;
            progress.done += stats.dirs + stats.files;
            if (deep && emit_stats(out, 0, &stats, &started) != 0) {
                free(st.kept);
                gaudit_secret_scan_set_progress(NULL, NULL);
                return 1;
            }
        }
        /* The folders the user added, full collection only. */
        char roots[GAUDIT_SECRETS_MAX_AREAS][PATH_MAX];
        snprintf(roots[0], sizeof roots[0], "%s", pw->pw_dir);
        unsigned n_roots = 1;
        for (size_t k = 0; deep && st.sum.status == GAUDIT_SECRETS_OK && k < n_folders
                           && n_roots < GAUDIT_SECRETS_MAX_AREAS; k++) {
            char real[PATH_MAX];
            gaudit_area_status status = GAUDIT_AREA_SEARCHED;
            if (folders[k][0] != '/' || strlen(folders[k]) >= sizeof ((gaudit_secret_area *)0)->path
                || realpath(folders[k], real) == NULL
                || strlen(real) >= sizeof ((gaudit_secret_area *)0)->path)
                status = GAUDIT_AREA_UNREADABLE;  /* also: too long to name in the report */
            for (unsigned r = 0; status == GAUDIT_AREA_SEARCHED && r < n_roots; r++)
                if (within(real, roots[r]) || within(roots[r], real))
                    status = GAUDIT_AREA_OVERLAPS;  /* searched already, or holding one */
            const char *shown = status == GAUDIT_AREA_UNREADABLE ? folders[k] : real;
            /* An area that cannot be opened is named as such; one that can is
             * named before its search, and how it went follows. */
            if (status == GAUDIT_AREA_SEARCHED && access(real, R_OK | X_OK) != 0)
                status = GAUDIT_AREA_UNREADABLE;
            if (emit_area(out, status == GAUDIT_AREA_SEARCHED ? n_roots : 0, shown, status) != 0) {
                free(st.kept);
                gaudit_secret_scan_set_progress(NULL, NULL);
                return 1;
            }
            if (status != GAUDIT_AREA_SEARCHED)
                continue;
            gaudit_secret_stats area_stats;
            memset(&area_stats, 0, sizeof area_stats);
            struct timespec area_start;
            clock_gettime(CLOCK_MONOTONIC, &area_start);
            st.area = n_roots;
            progress_where(&progress, real);
            if (gaudit_secret_scan_area(real, getuid(), on_hit, &st, &area_stats) == 0) {
                st.sum.truncated |= area_stats.truncated;
                progress.done += area_stats.dirs + area_stats.files;
            }
            if (emit_stats(out, n_roots, &area_stats, &area_start) != 0) {
                free(st.kept);
                gaudit_secret_scan_set_progress(NULL, NULL);
                return 1;
            }
            snprintf(roots[n_roots++], sizeof roots[0], "%s", real);
        }
    }
    if (st.sum.status != GAUDIT_SECRETS_OK) {
        /* Nothing from a failed search counts. */
        st.sum = (gaudit_secrets_summary){ .status = GAUDIT_SECRETS_UNKNOWN };
        st.n_kept = 0;
    }
    qsort(st.kept, st.n_kept, sizeof *st.kept, by_reach);
    char line[1024];
    for (unsigned i = 0; i < st.n_kept && st.sum.shown < GAUDIT_SECRETS_MAX_SHOWN; i++) {
        if (gaudit_secrets_format_finding(&st.kept[i], line, sizeof line) != 0 || fputs(line, out) == EOF) {
            free(st.kept);
            gaudit_secret_scan_set_progress(NULL, NULL);
            return 1;
        }
        st.sum.shown++;
    }
    free(st.kept);
    gaudit_secret_scan_set_progress(NULL, NULL);
    if (gaudit_secrets_format_summary(&st.sum, line, sizeof line) != 0 || fputs(line, out) == EOF)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

/* For the known locations check of one path. */
typedef struct {
    const char *rel;
    int found;
    gaudit_private_rule rule;
} item_known;

static void on_item_known(const char *rel, gaudit_private_rule rule, void *ctx)
{
    item_known *k = ctx;
    const char *mine = strcmp(k->rel, ".") == 0 ? "" : k->rel;
    if (strcmp(rel, mine) == 0) {
        k->found = 1;
        k->rule = rule;
    }
}

/* "secrets item <area> <root> <path>": one finding checked again, by the
 * same rules as the collection (the known locations first, for the home
 * folder). Area 0 is always the home folder from the password database,
 * whatever root says. */
static int check_item(const char *index_text, const char *root, const char *rel)
{
    char *end;
    unsigned long index = strtoul(index_text, &end, 10);
    const struct passwd *pw = getpwuid(getuid());
    if (*end != '\0' || index >= GAUDIT_SECRETS_MAX_AREAS || pw == NULL || pw->pw_dir == NULL
        || rel == NULL || rel[0] == '\0' || rel[0] == '/' || strstr(rel, "..") != NULL)
        return 2;
    if (index == 0)
        root = pw->pw_dir;
    scan_state st = { 0 };
    st.me = pw;
    st.own_gid_private = own_private_group(pw);
    snprintf(st.home, sizeof st.home, "%s", pw->pw_dir);
    st.area = (unsigned)index;
    st.kept = calloc(1, sizeof *st.kept);
    if (st.kept == NULL)
        return 1;
    if (index == 0) {
        item_known k = { .rel = rel };
        gid_t own_gid = st.own_gid_private ? pw->pw_gid : (gid_t)-1;
        if (gaudit_private_files_each(pw->pw_dir, getuid(), own_gid, on_item_known, &k) >= 0 && k.found)
            on_known(strcmp(rel, ".") == 0 ? "" : rel, k.rule, &st);
    }
    if (st.n_kept == 0 && strcmp(rel, ".") != 0) {
        gaudit_secret_hit hit;
        int r = gaudit_secret_check_one(root, index > 0, rel, getuid(), &hit);
        if (r < 0) {
            free(st.kept);
            return 1;
        }
        if (r == 1)
            on_hit(&hit, &st);
    }
    char line[1024];
    int ok;
    if (st.n_kept == 1)
        ok = gaudit_secrets_format_finding(&st.kept[0], line, sizeof line) == 0 && fputs(line, stdout) != EOF;
    else
        ok = fputs("(secret-gone)\n", stdout) != EOF;
    free(st.kept);
    return ok && fflush(stdout) == 0 ? 0 : 1;
}

int gaudit_private_files_secrets(const char *level, const char *const *folders, size_t n_folders)
{
    if (level != NULL && strcmp(level, "item") == 0)
        return n_folders == 3 ? check_item(folders[0], folders[1], folders[2]) : 2;
    /* "--with-caches" first, if given: caches are searched too. */
    if (n_folders > 0 && strcmp(folders[0], "--with-caches") == 0) {
        gaudit_secret_scan_set_caches(1);
        folders++;
        n_folders--;
    }
    /* "--read-limit=N" before the folders: one of the allowed sizes. */
    static const char opt[] = "--read-limit=";
    if (n_folders > 0 && strncmp(folders[0], opt, sizeof opt - 1) == 0) {
        char *end;
        unsigned long n = strtoul(folders[0] + sizeof opt - 1, &end, 10);
        if (*end != '\0' || gaudit_secret_scan_set_read_limit(n) != 0)
            return 2;
        folders++;
        n_folders--;
    }
    int deep = level != NULL && strcmp(level, "full") == 0;
    if (level == NULL || (!deep && strcmp(level, "quick") != 0))
        return 2;
    /* The home directory from the password database, not from $HOME. */
    if (!deep && n_folders > 0)
        return 2;  /* the quick collection is the home folder's only */
    return gaudit_private_files_collect(getpwuid(getuid()), deep, folders, n_folders, stdout);
}
