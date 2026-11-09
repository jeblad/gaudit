/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <locale.h>

#include "gaudit-app.h"

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    /* Compiled-in path only: a user-controlled translation catalog could make
     * a red finding read as green. */
    bindtextdomain(GETTEXT_PACKAGE, GAUDIT_LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);
    g_set_application_name(GAUDIT_APP_NAME);

    g_autoptr(GauditApp) app = gaudit_app_new();
    return g_application_run(G_APPLICATION(app), argc, argv);
}
