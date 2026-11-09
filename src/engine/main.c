/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-engine: evaluates verified Guile rules in ice-9 sandbox.
 * Rules return language-neutral message IDs + parameters; the GUI
 * translates. Not implemented yet.
 */
#include "config.h"

#include <stdio.h>

int main(void)
{
    fputs("gaudit-engine " GAUDIT_VERSION ": not implemented\n", stderr);
    return 2;
}
