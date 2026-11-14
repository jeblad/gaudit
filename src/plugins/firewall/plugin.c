/* SPDX-License-Identifier: GPL-3.0-only */
/* The Firewall plugin's description, in C until the plugin description
 * format exists; it then moves to it, marked core. */
#include "config.h"

#include "gaudit-plugins.h"

#include <glib/gi18n.h>

const GauditTaskInfo gaudit_plugin_firewall = {
    .id = "core.firewall",
    .title = N_("Firewall"),
    .summary = N_("Checks that a firewall is actually filtering incoming network traffic."),
    .details = N_("A firewall decides which connections from other computers may reach "
                  "this one. Having a firewall program installed is not enough: it also "
                  "has to be switched on. This check looks at the rules the system is "
                  "using right now, whichever program set them up.\n\n"
                  "Reading the rules needs the administrator password, because only the "
                  "administrator may look at them. gAudit only reads the rules; it "
                  "changes nothing."),
    .icon = "gaudit-fire-symbolic",
    .capabilities = NULL,  /* reads the kernel's rules: nothing to install */
    .params = NULL,
    .n_params = 0,
    .run_command = "run firewall",
    .home_probe = "status.firewall",
    .home_tooltip = N_("Thorough check of the firewall"),
    .home_level = GAUDIT_LEVEL_NORMAL,  /* under a second */
    .home_title = N_("Firewall rules"),
    .needs_admin = TRUE,
    .run_waiting = N_("Reading the firewall rules needs the administrator password."),
    .run_running = N_("Checking the firewall…"),
};
