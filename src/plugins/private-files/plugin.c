/* SPDX-License-Identifier: GPL-3.0-only */
/* The Private Files plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. */
#include "config.h"

#include "gaudit-plugins.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_private_files = {
    .id = "core.private-files",
    .title = N_("Private Files"),
    .summary = N_("Searches your whole home folder for keys, passwords and other secrets that "
                  "others could read."),
    .details = N_("Home checks the places where programs usually keep secrets. This search goes "
                  "through your whole home folder and finds private keys, password databases and "
                  "stored logins wherever they are, for example a key copied to the desktop.\n\n"
                  "For each one it looks at who besides you can read it, taking every folder on "
                  "the way into account. A secret only you can read is normal, such as your SSH "
                  "keys; one others can read is a warning.\n\n"
                  "It reads only the start of small files to recognise them, never shows their "
                  "content, and keeps nothing: the list lives on screen only. It needs no "
                  "password and changes nothing."),
    .icon = "gaudit-private-files-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    .run_command = "user secrets",
    .home_probe = "status.private-files",
    .home_tooltip = N_("Search your whole home folder"),
    .home_level = GAUDIT_LEVEL_THOROUGH,  /* about 10 s on a large home */
    .home_title = N_("Secrets anywhere in your home folder"),
    .needs_admin = FALSE,
    .run_waiting = N_("Searching your home folder…"),
    .run_running = N_("Searching your home folder… This takes a few seconds."),
};
