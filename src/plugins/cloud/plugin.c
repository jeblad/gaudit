/* SPDX-License-Identifier: GPL-3.0-only */
/* The Cloud Services plugin's description, in C until the plugin
 * description format exists; it then moves to it, marked core. It finds
 * file synchronisation clients and their folders, and says what each
 * service's properties are; it never moves, writes or runs anything. */
#include "config.h"

#include "gaudit-cloud.h"
#include "gaudit-plugins.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_cloud = {
    .id = "core.cloud",
    .title = N_("Cloud Services"),
    .summary = N_("Finds the programs that keep a copy of your files in a cloud service, and "
                  "says who can read what is sent there."),
    .details = N_("Cloud Services looks for programs that synchronise a folder with a cloud "
                  "service, such as Dropbox, Nextcloud, OneDrive, Google Drive, MEGA or "
                  "Jottacloud, and finds where their folders are. For each service it says what "
                  "is known: whether files are encrypted before they leave the computer, so the "
                  "provider cannot read them; which country's law the provider is under; "
                  "whether the program's source code is open; and whether the system keeps it "
                  "up to date.\n\n"
                  "It also says where a program in between logs in to the service for you: if "
                  "that login goes through the program maker's own web service, they can reach "
                  "your files too.\n\n"
                  "It only finds out. It never moves a cloud folder: that is done in each "
                  "program's own settings, since moving it any other way can make the program "
                  "think your files were deleted."),
    .why = N_("What is in a cloud folder leaves the computer and is kept by someone else. "
              "Knowing which services are set up, and who can read what is sent there, is the "
              "first step to deciding whether that is what you want."),
    .about_parameters = N_("There is nothing to set yet."),
    .about_report = N_("The report lists the cloud services found, with their folders and what "
                       "is known about each. A service where the provider can read your files is a "
                       "warning, and so is a login that goes through someone else's web service, "
                       "or one whose making is not documented. A program the system does not keep "
                       "up to date is a recommendation.\n\n"
                       "The full report, and Home at the Thorough level, also look in the cloud "
                       "folders kept on this computer for files that look like secrets, such as "
                       "keys and stored logins: one where the provider can read it is a warning, "
                       "and so is one where that is unclear. A file that is encrypted with its own "
                       "password, such as a KeePass database, is a recommendation to move it to "
                       "the private disk."),
    .icon = "folder-remote-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    .run_command = "user cloud full",
    /* Thorough also searches the cloud folders kept on this computer for
     * secrets, which takes time on a large folder. */
    .home_commands = { [GAUDIT_LEVEL_QUICK] = "user cloud quick",
                       [GAUDIT_LEVEL_THOROUGH] = "user cloud full" },
    .home_title = N_("Cloud services"),
    .home_tooltip = N_("See the cloud services on this computer"),
    .collection_line = gaudit_cloud_line_ok,
    .text_domain = GAUDIT_CLOUD_DOMAIN,
    .fix_page = gaudit_cloud_fix_page,
    .extra_title = N_("Set Up With rclone"),
    .extra_icon = "list-add-symbolic",
    .extra_page = gaudit_cloud_setup_page,
    .run_waiting = N_("Looking for cloud services…"),
    .run_running = N_("Looking for cloud services…"),
};
