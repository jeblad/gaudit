/* SPDX-License-Identifier: GPL-3.0-only */
/* "gaudit-orchestrator secrets quick|full": the plugin's collection, as the
 * user. quick: the known locations only (fast, for Home). full: the same
 * known locations first, then the deep scan of the whole home directory; a
 * path is reported once. So the full collection always holds everything
 * the quick one finds: a deeper level adds to the collection, it does not
 * replace it, and only the presentation differs. Reports path, reason, mode and reach,
 * never any content. Those others can reach come first, so they are always
 * among the findings sent. */
#include "secrets-mode.h"

#include "private-files.h"
#include "secret-scan.h"
#include "secrets.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Findings kept for sorting; beyond this they are counted only. */
#define MAX_KEPT 4096

typedef struct {
    const struct passwd *me;
    int own_gid_private;          /* the user's primary group is their own private group */
    char home[4096];
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
        if (strcmp(st->kept[i].path, rel) == 0)
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

int gaudit_private_files_collect(const struct passwd *pw, int deep, FILE *out)
{
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
        if (gaudit_private_files_each(pw->pw_dir, getuid(), own_gid, on_known, &st) >= 0
            && (!deep || gaudit_secret_scan(pw->pw_dir, getuid(), on_hit, &st, &stats) == 0)) {
            st.sum.status = GAUDIT_SECRETS_OK;
            st.sum.truncated = stats.truncated;
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
            return 1;
        }
        st.sum.shown++;
    }
    free(st.kept);
    if (gaudit_secrets_format_summary(&st.sum, line, sizeof line) != 0 || fputs(line, out) == EOF)
        return 1;
    return fflush(out) == 0 ? 0 : 1;
}

int gaudit_private_files_secrets(const char *level)
{
    int deep = level != NULL && strcmp(level, "full") == 0;
    if (level == NULL || (!deep && strcmp(level, "quick") != 0))
        return 2;
    /* The home directory from the password database, not from $HOME. */
    return gaudit_private_files_collect(getpwuid(getuid()), deep, stdout);
}
