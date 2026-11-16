/* SPDX-License-Identifier: GPL-3.0-only */
/* The GUI's own environment. Its children get an empty one, but the GUI
 * itself starts with whatever the desktop gives it, and some variables
 * make a program load code it would not otherwise (LD_PRELOAD,
 * GTK_MODULES, GIO_EXTRA_MODULES ...). gAudit starts itself again without
 * them, before GTK is loaded, and says so on Home. Plain C, no GLib, so it
 * runs before anything else. */
#pragma once

#include <stddef.h>

/* 1 when an environment entry ("NAME=value") is one gAudit removes. */
int gaudit_environ_unwanted(const char *entry);

/* At the very start of main: when any unwanted variable is set, starts the
 * program again (/proc/self/exe, the same arguments) without them, telling
 * the new start which they were; does not return then. Otherwise returns,
 * and remembers what an earlier start removed. */
void gaudit_environ_clean(char *argv[]);

/* The names an earlier start removed, ", " between, or NULL for none. */
const char *gaudit_environ_removed(void);
