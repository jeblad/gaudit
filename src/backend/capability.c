/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/backend.h"

#include <stddef.h>
#include <unistd.h>

int gaudit_capability_present(const gaudit_capability *cap)
{
    if (cap == NULL || cap->paths == NULL || cap->paths[0] == NULL)
        return 0;
    for (const char *const *p = cap->paths; *p != NULL; p++)
        if (access(*p, X_OK) != 0)
            return 0;
    return 1;
}

const gaudit_pkg_backend *gaudit_pkg_backend_default(void)
{
    /* TODO: select the backend from the detected distro. */
    return gaudit_pkg_backend_ubuntu();
}
