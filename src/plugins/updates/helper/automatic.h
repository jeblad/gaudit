/* SPDX-License-Identifier: GPL-3.0-only */
/* Automatic updates on Debian and Ubuntu, as a drop-in of gAudit's own:
 * the first configuration gAudit writes. The decision is fixed (on, or
 * gAudit's file removed again), the file comes from a fixed template, and
 * conf-write.h decides whether it may be written at all. */
#pragma once

#include "conf-write.h"

#define GAUDIT_AUTOMATIC_PATH     "etc/apt/apt.conf.d/52gaudit-automatic-updates"
#define GAUDIT_AUTOMATIC_TEMPLATE "core.updates.automatic"

/* Writes the drop-in that switches automatic updates on. Needs
 * unattended-upgrades installed. */
gaudit_conf_result gaudit_automatic_updates_on(const gaudit_conf_env *env);

/* Removes it again, only while it is exactly as gAudit wrote it. */
gaudit_conf_result gaudit_automatic_updates_remove(const gaudit_conf_env *env);

/* The template's content, for tests. */
extern const char gaudit_automatic_content[];
