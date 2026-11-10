/* SPDX-License-Identifier: GPL-3.0-only */
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <seccomp.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int gaudit_sandbox_close_fds(int keep_fd)
{
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDERR_FILENO) < 0)
        return -1;
    if (null > STDERR_FILENO && null != keep_fd)
        close(null);

    /* close_range covers everything without scanning /proc. */
    if (keep_fd < 0 || keep_fd <= STDERR_FILENO)
        return syscall(SYS_close_range, 3U, ~0U, 0) == 0 ? 0 : -1;
    if (keep_fd > 3 && syscall(SYS_close_range, 3U, (unsigned)keep_fd - 1, 0) != 0)
        return -1;
    return syscall(SYS_close_range, (unsigned)keep_fd + 1, ~0U, 0) == 0 ? 0 : -1;
}

/* Things no check ever needs. The filter is a deny list on purpose: checks
 * read files and /proc, and an allow list would break on new glibc and
 * kernel versions. Denied calls fail with EPERM. */
static const int denied_syscalls[] = {
    SCMP_SYS(ptrace), SCMP_SYS(process_vm_readv), SCMP_SYS(process_vm_writev),
    SCMP_SYS(mount), SCMP_SYS(umount2), SCMP_SYS(pivot_root), SCMP_SYS(chroot),
    SCMP_SYS(move_mount), SCMP_SYS(open_tree), SCMP_SYS(fsopen), SCMP_SYS(fsmount),
    SCMP_SYS(kexec_load), SCMP_SYS(kexec_file_load), SCMP_SYS(reboot),
    SCMP_SYS(init_module), SCMP_SYS(finit_module), SCMP_SYS(delete_module),
    SCMP_SYS(bpf), SCMP_SYS(perf_event_open), SCMP_SYS(userfaultfd),
    SCMP_SYS(keyctl), SCMP_SYS(add_key), SCMP_SYS(request_key),
    SCMP_SYS(setns), SCMP_SYS(unshare), SCMP_SYS(swapon), SCMP_SYS(swapoff),
    SCMP_SYS(open_by_handle_at), SCMP_SYS(name_to_handle_at),
    SCMP_SYS(iopl), SCMP_SYS(ioperm), SCMP_SYS(acct), SCMP_SYS(settimeofday),
    SCMP_SYS(clock_settime), SCMP_SYS(sethostname), SCMP_SYS(setdomainname),
};

int gaudit_sandbox_restrict(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return -1;
    int rc = 0;
    for (size_t i = 0; i < sizeof denied_syscalls / sizeof denied_syscalls[0] && rc == 0; i++)
        if (denied_syscalls[i] >= 0)  /* not every call exists on every architecture */
            rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), denied_syscalls[i], 0);
    /* No network: checks read local state only. */
    static const int families[] = { AF_INET, AF_INET6, AF_PACKET };
    for (size_t i = 0; i < sizeof families / sizeof families[0] && rc == 0; i++)
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                              SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)families[i]));
    if (rc == 0)
        rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc == 0 ? 0 : -1;
}

static int is_kept(cap_value_t c, const cap_value_t *caps, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (caps[i] == c)
            return 1;
    return 0;
}

/* Limit what the process can ever gain: drop every capability not in caps
 * from the bounding set, and clear the ambient set. Leaves the current
 * capabilities alone, so setresuid/setresgid still work afterwards. */
static int limit_bounding(const cap_value_t *caps, size_t n)
{
    for (cap_value_t c = 0; c <= CAP_LAST_CAP; c++)
        if (!is_kept(c, caps, n) && prctl(PR_CAPBSET_DROP, c, 0, 0, 0) != 0 && errno != EINVAL)
            return -1;
    return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0 ? 0 : -1;
}

/* Exactly caps as permitted and effective, nothing inheritable. */
static int set_caps(const cap_value_t *caps, size_t n)
{
    cap_t state = cap_init();  /* all clear */
    if (state == NULL)
        return -1;
    int rc = 0;
    if (n > 0)
        rc = cap_set_flag(state, CAP_PERMITTED, (int)n, caps, CAP_SET) != 0
          || cap_set_flag(state, CAP_EFFECTIVE, (int)n, caps, CAP_SET) != 0;
    if (rc == 0)
        rc = cap_set_proc(state);
    cap_free(state);
    return rc == 0 ? 0 : -1;
}

int gaudit_sandbox_enter(const gaudit_sandbox *spec)
{
    if (spec == NULL || clearenv() != 0)
        return -1;
    umask(077);
    if (chdir("/") != 0)
        return -1;

    if (spec->to_nobody) {
        /* Empty the bounding set while still root, then become nobody; the
         * kernel clears the current capabilities on the uid change. */
        if (limit_bounding(NULL, 0) != 0
            || setgroups(0, NULL) != 0
            || setresgid(GAUDIT_NOBODY_GID, GAUDIT_NOBODY_GID, GAUDIT_NOBODY_GID) != 0
            || setresuid(GAUDIT_NOBODY_UID, GAUDIT_NOBODY_UID, GAUDIT_NOBODY_UID) != 0)
            return -1;
        /* It must not be possible to get root back. */
        if (setresuid(0, 0, 0) == 0)
            return -1;
    } else {
        if (limit_bounding(spec->caps, spec->n_caps) != 0
            || setgroups(0, NULL) != 0
            || set_caps(spec->caps, spec->n_caps) != 0)
            return -1;
    }
    return gaudit_sandbox_restrict();
}
