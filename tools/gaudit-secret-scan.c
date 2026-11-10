/* SPDX-License-Identifier: GPL-3.0-only */
/* Developer tool (dev builds only): searches the caller's home directory
 * for files that look like secrets and prints one line per file:
 *
 *   <reach> <mode> <reason> ~/<path>
 *
 * reach is "owner", "group:<name>" or "OTHERS" (others can read it, taking
 * the folders on the way into account). A group that is the user's own
 * private group with no other members (as Ubuntu creates them) counts as
 * owner, shown as "own-grp". A "!" before the mode marks a file owned by
 * someone else. Only names and modes are printed, never content. Meant for finding
 * out where secrets live, so Home can be taught those locations.
 * Read-only; needs no privileges. */
#include "secret-scan.h"

#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static const struct passwd *me;

/* The user's own private group: same name and primary gid, no members
 * besides the user. Other accounts with this as their primary group are
 * not looked for. */
static int own_group(gid_t gid)
{
    if (gid != me->pw_gid)
        return 0;
    struct group *gr = getgrgid(gid);
    if (gr == NULL || strcmp(gr->gr_name, me->pw_name) != 0)
        return 0;
    for (char **m = gr->gr_mem; *m != NULL; m++)
        if (strcmp(*m, me->pw_name) != 0)
            return 0;
    return 1;
}

/* File names come from the disk: print control bytes escaped, so a crafted
 * name cannot drive the terminal. */
static void print_path(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == '\\')
            printf("\\x%02x", *p);
        else
            putchar(*p);
    }
}

static void print_hit(const gaudit_secret_hit *hit, void *ctx)
{
    unsigned *counts = ctx;
    char reach[48];
    int slot = hit->reach;
    if (hit->reach == GAUDIT_REACH_OTHERS) {
        snprintf(reach, sizeof reach, "OTHERS");
    } else if (hit->reach == GAUDIT_REACH_GROUP && own_group(hit->gid)) {
        snprintf(reach, sizeof reach, "own-grp");
        slot = 3;
    } else if (hit->reach == GAUDIT_REACH_GROUP) {
        struct group *gr = getgrgid(hit->gid);
        if (gr != NULL)
            snprintf(reach, sizeof reach, "group:%s", gr->gr_name);
        else
            snprintf(reach, sizeof reach, "group:%u", (unsigned)hit->gid);
    } else {
        snprintf(reach, sizeof reach, "owner");
    }
    counts[slot]++;
    printf("%-12s %s%04o %-20s ~/", reach, hit->owned ? " " : "!", (unsigned)hit->mode, hit->reason);
    print_path(hit->rel);
    putchar('\n');
}

int main(void)
{
    /* The home directory from the password database, not from $HOME. */
    struct passwd *pw = getpwuid(getuid());
    me = pw;
    if (pw == NULL || pw->pw_dir == NULL) {
        fputs("gaudit-secret-scan: no home directory\n", stderr);
        return 1;
    }
    unsigned counts[4] = { 0, 0, 0, 0 };  /* owner, group, others, own group */
    gaudit_secret_stats st;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (gaudit_secret_scan(pw->pw_dir, getuid(), print_hit, counts, &st) != 0) {
        fputs("gaudit-secret-scan: cannot open the home directory\n", stderr);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("-- %u owner-only, %u own group, %u other groups, %u others | %u folders, %u files (%u read), "
           "%u folders skipped%s, %.1f s\n",
           counts[0], counts[3], counts[1], counts[2], st.dirs, st.files, st.read, st.skipped,
           st.truncated ? ", STOPPED at the entry limit" : "", secs);
    return 0;
}
