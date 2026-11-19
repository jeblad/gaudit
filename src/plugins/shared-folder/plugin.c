/* SPDX-License-Identifier: GPL-3.0-only */
/* The Shared Folder plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. A proof of concept for
 * the known folders: the public share folder only (cloud folders get a
 * plugin of their own). */
#include "config.h"

#include "gaudit-plugins.h"
#include "gaudit-shared-folder.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_shared_folder = {
    .id = "core.shared-folder",
    .title = N_("Shared Folder"),
    .summary = N_("Finds the folder meant for sharing on the local network, and other folders "
                  "that look like it."),
    .details = N_("A desktop that follows the usual standard has one folder for what you share "
                  "with others on the local network, called Public in English. Its name follows "
                  "the language you had when you first logged in, so after a change of language "
                  "there can be two, such as Offentlig and Public, and it becomes unclear which "
                  "one is shared.\n\n"
                  "Shared Folder finds the folder in use and every other folder in your home "
                  "folder with a name it could have had, in any language and from older "
                  "versions. It also looks for what shares folders: Samba, including the "
                  "sharing you do from the file manager, and GNOME Sharing. It needs no "
                  "password.\n\n"
                  "It can tidy a duplicate: move what is in it into the folder in use, never "
                  "replacing anything, and remove it once it is empty. It never deletes files, "
                  "and changes nothing while something shares one of the folders."),
    .why = N_("What is in a shared folder can be read by others on the same network, at home "
              "or on a café's Wi-Fi. With two folders for the same thing, it is easy to put a "
              "file in the one that is shared when you meant the other, or the other way "
              "round. Sharing is often switched on without people knowing it."),
    .about_parameters = N_("There is nothing to set yet. Later you will be asked which folder you "
                           "mean to use for sharing, and whether the sharing found is meant."),
    .about_report = N_("The report shows the folder in use for sharing, the other folders that "
                       "look like it, and what shares folders on this computer. A folder that "
                       "looks like it leads to a page that can tidy it.\n\n"
                       "It also looks in them for files that look like secrets, such as keys and "
                       "stored logins, put there by mistake: in a folder shared on the local "
                       "network, a warning; in a folder for sharing that nothing shares now, a "
                       "recommendation. The full report, and Home at the Thorough level, also "
                       "search every other folder a service shares. A folder on another disk, a "
                       "network folder or a link is not searched."),
    .icon = "folder-publicshare-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    .run_command = "user shared full",
    /* Thorough also searches every folder a service shares for secrets. */
    .home_commands = { [GAUDIT_LEVEL_QUICK] = "user shared quick",
                       [GAUDIT_LEVEL_THOROUGH] = "user shared full" },
    .home_title = N_("The shared folder"),
    .home_tooltip = N_("See the shared folder and what shares folders"),
    .collection_line = gaudit_shared_folder_line,
    .text_domain = GAUDIT_SHARED_FOLDER_DOMAIN,
    .fix_page = gaudit_shared_folder_fix_page,
    .run_waiting = N_("Looking at your folders…"),
    .run_running = N_("Looking at your folders…"),
};
