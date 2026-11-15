/* SPDX-License-Identifier: GPL-3.0-only */
/* The Updates plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. */
#include "config.h"

#include "gaudit-plugins.h"
#include "gaudit-updates.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_updates = {
    .id = "core.updates",
    .title = N_("Updates"),
    .summary = N_("Checks that this computer looks for updates, installs them, and gets them "
                  "from the right place."),
    .details = N_("Updates checks how updates reach this computer: how often it looks for them, "
                  "whether it installs them by itself, whether security updates are waiting, "
                  "where security updates come from, and whether installed software is left "
                  "without any source of updates.\n\n"
                  "It reads how the computer is set up, not what an update program shows, so "
                  "it says the same whichever program you use for updates.\n\n"
                  "The full report, and Home at Thorough, also check the package files: every "
                  "program installed from a package comes with a checksum for each of its "
                  "files, and every file is compared with it, so a changed or missing file "
                  "shows up, whoever changed it. Your own settings in /etc are not counted. "
                  "This reads tens of thousands of files, can take several minutes, and needs "
                  "the administrator password. A clean result means no changes were found, not "
                  "that the computer is proven clean: the checksums are not signed once "
                  "installed.\n\n"
                  "Updates changes nothing."),
    .why = N_("Most attacks use problems that already have a fix. A computer that does not "
              "install its updates keeps those problems open, often for weeks, and security "
              "updates matter most."),
    .about_parameters = NULL,
    .about_report = N_("The report is grouped by what can go wrong: looking for updates, "
                       "installing them, where security updates come from, software no source "
                       "keeps up to date, package systems that are not checked, and, in the full "
                       "report, package files that were changed. Each problem is marked with a "
                       "warning and leads on to what to do about it."),
    .icon = "gaudit-packages-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    /* The facts as the user, then the package files in the helper, as
     * one collection. */
    .run_command = "user updates quick then run integrity",
    .home_probe = NULL,
    .home_tooltip = N_("Check how updates reach this computer"),
    .home_commands = { [GAUDIT_LEVEL_QUICK] = "user updates quick",
                       /* a minute or more, and the password */
                       [GAUDIT_LEVEL_THOROUGH] = "user updates quick then run integrity" },
    .home_title = N_("Updates"),
    .collection_line = gaudit_updates_line,
    .text_domain = GAUDIT_UPDATES_DOMAIN,
    .fix_page = gaudit_updates_fix_page,
    .backend = NULL,  /* every backend: what one cannot tell, the report says */
    .helper_backend = "debian",  /* the package files: dpkg's md5sums */
    .run_waiting = N_("Checking the package files needs the administrator password."),
    .run_running = N_("Checking how updates reach this computer… The package files can take a few minutes."),
};
