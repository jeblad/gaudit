/* SPDX-License-Identifier: GPL-3.0-only */
#include "automatic.h"

#include <string.h>

/* apt reads apt.conf.d in byte order and the last value wins, so this
 * comes after Debian's and Ubuntu's own files (10periodic, 20auto-upgrades)
 * and before the 99... a local administrator usually picks. If one of
 * those turns it off again, the check afterwards says so; gAudit never
 * touches it. Flat "Key "value";" lines only, the form gAudit's own reader
 * understands. Which updates are installed stays as unattended-upgrades is
 * set up (security updates on Debian and Ubuntu). The comment is in
 * English, since the helper never translates. */
const char gaudit_automatic_content[] =
    "// Written by gAudit: automatic updates on.\n"
    "// Looks for updates every day and installs them as unattended-upgrades\n"
    "// is set up (on Debian and Ubuntu: security updates).\n"
    "// gAudit replaces or removes this file only while it is exactly as\n"
    "// written. To change it, use gAudit's Updates page.\n"
    "APT::Periodic::Update-Package-Lists \"1\";\n"
    "APT::Periodic::Unattended-Upgrade \"1\";\n";

/* Without the program, the setting would do nothing. */
static const gaudit_conf_expect needs[] = {
    { "usr/bin/unattended-upgrade", GAUDIT_EXPECT_PRESENT, NULL },
};

gaudit_conf_result gaudit_automatic_updates_on(const gaudit_conf_env *env)
{
    gaudit_conf_plan plan = {
        .path = GAUDIT_AUTOMATIC_PATH,
        .template_id = GAUDIT_AUTOMATIC_TEMPLATE,
        .values = "on",
        .content = gaudit_automatic_content,
        .len = strlen(gaudit_automatic_content),
        .mode = 0644,
        .expect = needs,
        .n_expect = sizeof needs / sizeof needs[0],
    };
    return gaudit_conf_write(env, &plan);
}

gaudit_conf_result gaudit_automatic_updates_remove(const gaudit_conf_env *env)
{
    return gaudit_conf_remove(env, GAUDIT_AUTOMATIC_PATH);
}
