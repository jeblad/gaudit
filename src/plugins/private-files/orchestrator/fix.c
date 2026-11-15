/* SPDX-License-Identifier: GPL-3.0-only */
/* "gaudit-orchestrator fix make-private|close-home <root> [<path>]": the
 * Private Files fixes, as the user, on request. Fixed operations that only
 * ever take access away (others' bits for a secret, others' write bit for
 * the home folder), so a fix can never open anything up, whoever asks for
 * it. The file is opened beneath root without following any symbolic link,
 * checked to be the user's, and changed through that open file, so it
 * cannot be swapped between the check and the change. No shell and no
 * chmod program. Writes "(fixed (mode M))" with the mode it now has. */
#include "fix-mode.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int plain_rel(const char *rel)
{
    if (rel[0] == '\0' || rel[0] == '/' || strlen(rel) >= 4096)
        return 0;
    for (const char *p = rel; *p != '\0'; p++)
        if ((unsigned char)*p < 0x20)
            return 0;
    return 1;
}

/* rel beneath root_fd, no symbolic link anywhere on the way. */
static int open_beneath(int root_fd, const char *rel)
{
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    return (int)syscall(SYS_openat2, root_fd, rel, &how, sizeof how);
}

int gaudit_private_files_fix(const char *fix_id, const char *root, const char *rel)
{
    int close_home = fix_id != NULL && strcmp(fix_id, "close-home") == 0;
    int private = fix_id != NULL && strcmp(fix_id, "make-private") == 0;
    if ((!close_home && !private) || root == NULL || root[0] != '/'
        || (private && (rel == NULL || !plain_rel(rel))) || (close_home && rel != NULL))
        return 2;
    int root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0)
        return 1;
    int fd = close_home ? dup(root_fd) : open_beneath(root_fd, rel);
    close(root_fd);
    if (fd < 0)
        return 1;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_uid != getuid()
        || (!S_ISREG(sb.st_mode) && !S_ISDIR(sb.st_mode))) {
        close(fd);
        return 1;  /* not the user's own file or folder */
    }
    /* Only ever take away: others' everything, or for the home folder
     * others' write. */
    mode_t mode = sb.st_mode & 07777 & (mode_t)~(close_home ? 022 : 077);
    char proc[64];
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    int r = chmod(proc, mode);  /* the open file itself, not a path again */
    if (r == 0 && fstat(fd, &sb) != 0)
        r = -1;
    close(fd);
    if (r != 0)
        return 1;
    printf("(fixed (mode %u))\n", (unsigned)(sb.st_mode & 07777));
    return fflush(stdout) == 0 ? 0 : 1;
}
