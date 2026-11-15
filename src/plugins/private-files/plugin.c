/* SPDX-License-Identifier: GPL-3.0-only */
/* The Private Files plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. */
#include "config.h"

#include "gaudit-plugins.h"
#include "gaudit-private-files.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_private_files = {
    .id = "core.private-files",
    .title = N_("Private Files"),
    .summary = N_("Searches your whole home folder for keys, passwords and other secrets that "
                  "others could read."),
    .details = N_("Private Files looks for secrets in your home folder, and in other folders you "
                  "add: private keys, password databases and stored logins, wherever they are, "
                  "for example a key copied to the desktop. For each one it looks at who besides "
                  "you can read it, taking every folder on the way into account. A secret only "
                  "you can read is normal, such as your SSH keys; one others can read is a "
                  "warning.\n\n"
                  "It reads only the start of small files to recognise them, never shows their "
                  "content, and keeps nothing: the list lives on screen only. It needs no "
                  "password. It changes nothing unless you ask it to fix a file, and then only "
                  "takes others' access away."),
    .why = N_("A key or password file others can read can be copied without you noticing, and "
              "gives access to what it protects: servers you log in to, your accounts, your "
              "passwords. Old copies count too: a key from a machine you no longer use may still "
              "open a server today."),
    .about_parameters = N_("Folders to Search: your home folder is always searched. Add folders "
                           "elsewhere on this computer or on a network, such as a disk with old "
                           "backups; the file manager's places outside your home folder are listed "
                           "too, and each can be removed from the list. Everything under each "
                           "folder is searched, within its own disk.\n\n"
                           "Read Files Up To: files up to this size have their start read, to "
                           "recognise a key in a file of any name. Larger files are recognised by "
                           "name only. Smaller is faster on large disks; even the smallest holds "
                           "every real key file.\n\n"
                           "Search Caches Too: caches are left out unless this is on. Programs "
                           "rebuild them and they seldom hold secrets, but they can take long on "
                           "large disks."),
    .about_report = N_("The report lists the secrets found: private keys, password databases and "
                       "stored logins, grouped by who besides you can read them. Each one others "
                       "can read is marked with a warning and leads on to a fix that makes it "
                       "readable by you only. Those only you can read are listed so you know "
                       "where they are.\n\n"
                       "The notes at the end say which folders were searched, where the search "
                       "stopped before the end, and what it left out."),
    .icon = "gaudit-private-files-symbolic",
    .capabilities = NULL,
    .params = NULL,
    .n_params = 0,
    .run_command = "user secrets full",
    .home_probe = "status.private-files",
    .home_tooltip = N_("Search your whole home folder"),
    /* Quick: the known places; Thorough: the whole home folder (about 10 s
     * on a large one). */
    .home_commands = { [GAUDIT_LEVEL_QUICK] = "user secrets quick",
                       [GAUDIT_LEVEL_THOROUGH] = "user secrets full" },
    .home_title = N_("Secrets in your home folder"),
    .needs_admin = FALSE,
    .collection_line = gaudit_private_files_line,
    .text_domain = GAUDIT_PRIVATE_FILES_DOMAIN,
    .param_folders = TRUE,
    .param_read_limit = TRUE,
    .param_caches = TRUE,
    .fix_page = gaudit_private_files_fix_page,
    .run_waiting = N_("Searching your home folder…"),
    .run_running = N_("Searching… Large folders can take a long time."),
};
