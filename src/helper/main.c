/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-helper: privileged helper, started via pkexec.
 *
 * Responsibilities (AGENTS.md): verify the signed manifest, fork the check
 * processes with privileges reduced per check, inspect the other gaudit
 * processes, write the root-owned log.
 *
 * Never translates output: it runs as root, and its output is a
 * language-neutral protocol. Not implemented yet.
 */
#include "config.h"

#include <stdio.h>

int main(void)
{
    fputs("gaudit-helper " GAUDIT_VERSION ": not implemented\n", stderr);
    return 2;
}
