/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. */
#include "config.h"

#include "gaudit-plugins.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_updates = {
    .id = "core.updates",
    .title = N_("Updates"),
    .summary = N_("Checks that your software is kept up to date, and that the files it was "
                  "installed with have not been changed since."),
    .details = N_("Home shows whether updates are found and installed. The thorough check "
                  "here goes further.\n\n"
                  "Every program installed from a package comes with a list of its files "
                  "and a checksum for each. This check reads every one of those files and "
                  "compares it with its checksum, so a changed or missing file shows up, "
                  "whether a person, a program or malware changed it. Your own settings "
                  "in /etc are not counted: changing them is normal.\n\n"
                  "It reads tens of thousands of files and can take from half a minute to "
                  "several minutes. Reading all of them needs the administrator password. "
                  "gAudit only reads; it changes nothing.\n\n"
                  "A clean result means no changes were found, not that the computer is "
                  "proven clean: the checksums are not signed once installed, so someone "
                  "with full control of the computer could change them too."),
    .icon = "gaudit-packages-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    .run_command = "run integrity",
    .home_probe = NULL,
    .home_tooltip = NULL,
    .home_level = GAUDIT_LEVEL_THOROUGH,  /* a minute or more */
    .home_title = N_("Package files"),
    .needs_admin = TRUE,
    .backend = "debian",  /* reads dpkg's md5sums */
    .run_waiting = N_("Reading every package file needs the administrator password."),
    .run_running = N_("Checking the package files… This can take a few minutes."),
};
