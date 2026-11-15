/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt-ops.h"

#include <stdio.h>
#include <string.h>

/* Changed settings files are kept, without a question: nothing could
 * answer one when it runs from the page. */
#define APT_GET "/usr/bin/apt-get", "-y", \
    "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"

static const char *const update_argv[] = { "/usr/bin/apt-get", "update", NULL };
static const char *const upgrade_argv[] = { APT_GET, "--with-new-pkgs", "upgrade", NULL };
/* apt 2.7.0 and newer: the lists first, in the same command. */
static const char *const upgrade_update_argv[] = { APT_GET, "--with-new-pkgs", "upgrade", "--update", NULL };
static const char *const timers_argv[] = {
    "/usr/bin/systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer", NULL,
};
static const char *const reinstall_argv[] = { APT_GET, "install", "--reinstall", NULL };

static const gaudit_apt_op ops[] = {
    { "apt-update",         update_argv,         0 },
    { "apt-upgrade",        upgrade_argv,        0 },
    { "apt-upgrade-update", upgrade_update_argv, 0 },
    { "enable-apt-timers",  timers_argv,         0 },
    { "reinstall",          reinstall_argv,      1 },
};

const gaudit_apt_op *gaudit_apt_op_find(const char *name)
{
    for (size_t i = 0; name != NULL && i < sizeof ops / sizeof ops[0]; i++)
        if (strcmp(ops[i].name, name) == 0)
            return &ops[i];
    return NULL;
}

static int append(char *buf, size_t len, size_t *used, const char *word)
{
    int n = snprintf(buf + *used, len - *used, "%s%s", *used > 0 ? " " : "", word);
    if (n < 0 || (size_t)n >= len - *used)
        return -1;
    *used += (size_t)n;
    return 0;
}

int gaudit_apt_op_shown(const gaudit_apt_op *op, const char *const *packages, size_t n_packages,
                        char *buf, size_t len)
{
    if (op == NULL || buf == NULL || len == 0 || (n_packages > 0 && !op->takes_packages))
        return -1;
    size_t used = 0;
    buf[0] = '\0';
    const char *program = strrchr(op->argv[0], '/');
    if (append(buf, len, &used, "sudo") != 0
        || append(buf, len, &used, program != NULL ? program + 1 : op->argv[0]) != 0)
        return -1;
    for (size_t i = 1; op->argv[i] != NULL; i++)
        if (append(buf, len, &used, op->argv[i]) != 0)
            return -1;
    for (size_t i = 0; i < n_packages; i++)
        if (!gaudit_apt_plain_package(packages[i]) || append(buf, len, &used, packages[i]) != 0)
            return -1;
    return 0;
}

int gaudit_apt_plain_package(const char *name)
{
    if (name == NULL)
        return 0;
    const char *colon = strchr(name, ':');
    size_t len = colon != NULL ? (size_t)(colon - name) : strlen(name);
    if (len < 2 || len > 100 || !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= '0' && name[0] <= '9')))
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'))
            return 0;
    }
    if (colon == NULL)
        return 1;
    if (colon[1] == '\0' || strlen(colon + 1) > 32)
        return 0;
    for (const char *c = colon + 1; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-'))
            return 0;
    return 1;
}
