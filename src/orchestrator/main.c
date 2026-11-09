/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-orchestrator: runs as the user. Starts the helper (pkexec) and the
 * rule engine, and hands verdicts to the GUI. Not implemented yet.
 */
#include "config.h"

#include <stdio.h>

int main(void)
{
    fputs("gaudit-orchestrator " GAUDIT_VERSION ": not implemented\n", stderr);
    return 2;
}
