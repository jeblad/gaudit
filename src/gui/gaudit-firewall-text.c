/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>

#include "gaudit-firewall-text.h"

void gaudit_firewall_text(const gaudit_firewall_report *f, const char **icon,
                          char **title, char **description)
{
    switch (f->verdict) {
    case GAUDIT_VERDICT_OK: {
        g_autofree char *how = f->input_drop > 0
            ? g_strdup(_("Incoming connections are blocked unless a rule allows them."))
            : g_strdup_printf(ngettext("Incoming connections pass through %u firewall rule.",
                                       "Incoming connections pass through %u firewall rules.",
                                       f->input_rules), f->input_rules);
        *icon = "security-high-symbolic";
        *title = g_strdup(_("The firewall is filtering incoming traffic"));
        /* Translators: Keep the meaning: active is not the same as right. */
        *description = g_strdup_printf("%s %s", how,
            _("This shows that a firewall is active, not that its rules suit you."));
        break;
    }
    case GAUDIT_VERDICT_UNKNOWN:
        *icon = "dialog-question-symbolic";
        *title = g_strdup(_("The firewall could not be checked fully"));
        *description = g_strdup(_("This system uses the older iptables, whose rules gAudit cannot read yet."));
        break;
    default:
        *icon = "security-low-symbolic";
        *title = g_strdup(_("No firewall is filtering incoming traffic"));
        /* What the missing firewall leaves open, counted when the check ran. */
        *description = f->listening == 0
            ? g_strdup(_("Nothing listens for connections from the network right now, so nothing "
                         "is exposed yet. A firewall still protects against services started later."))
            : g_strdup_printf(ngettext("%u service listens for connections from the network, and "
                                       "other computers can reach it.",
                                       "%u services listen for connections from the network, and "
                                       "other computers can reach them.", f->listening),
                              f->listening);
        break;
    }
}
