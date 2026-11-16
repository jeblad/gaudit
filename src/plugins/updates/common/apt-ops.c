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
/* Sets the PPA up for the release running, with its signing key from
 * Launchpad, and fetches the lists; -y: nothing could answer its question. */
static const char *const add_ppa_argv[] = { "/usr/bin/add-apt-repository", "-y", NULL };

static const gaudit_apt_op ops[] = {
    { "apt-update",         update_argv,         GAUDIT_APT_ARGS_NONE },
    { "apt-upgrade",        upgrade_argv,        GAUDIT_APT_ARGS_NONE },
    { "apt-upgrade-update", upgrade_update_argv, GAUDIT_APT_ARGS_NONE },
    { "enable-apt-timers",  timers_argv,         GAUDIT_APT_ARGS_NONE },
    { "reinstall",          reinstall_argv,      GAUDIT_APT_ARGS_PACKAGES },
    { "add-ppa",            add_ppa_argv,        GAUDIT_APT_ARGS_PPA },
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

int gaudit_apt_op_args_ok(const gaudit_apt_op *op, const char *const *args, size_t n_args)
{
    if (op == NULL || (n_args > 0 && args == NULL))
        return 0;
    switch (op->args) {
    case GAUDIT_APT_ARGS_NONE:
        return n_args == 0;
    case GAUDIT_APT_ARGS_PACKAGES:
        if (n_args == 0 || n_args > GAUDIT_APT_MAX_PACKAGES)
            return 0;
        for (size_t i = 0; i < n_args; i++)
            if (!gaudit_apt_plain_package(args[i]))
                return 0;
        return 1;
    case GAUDIT_APT_ARGS_PPA:
        return n_args == 1 && gaudit_apt_plain_ppa(args[0]);
    }
    return 0;
}

int gaudit_apt_op_shown(const gaudit_apt_op *op, const char *const *args, size_t n_args,
                        char *buf, size_t len)
{
    if (buf == NULL || len == 0 || !gaudit_apt_op_args_ok(op, args, n_args))
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
    for (size_t i = 0; i < n_args; i++)
        if (append(buf, len, &used, args[i]) != 0)
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

/* Launchpad's names: lower-case letters, digits, "+", "." and "-". */
static int plain_launchpad_name(const char *s, size_t len)
{
    if (len == 0 || len > 64 || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')))
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'))
            return 0;
    }
    return 1;
}

int gaudit_apt_plain_ppa(const char *ppa)
{
    if (ppa == NULL || strncmp(ppa, "ppa:", 4) != 0)
        return 0;
    const char *owner = ppa + 4, *slash = strchr(owner, '/');
    return slash != NULL && plain_launchpad_name(owner, (size_t)(slash - owner))
           && plain_launchpad_name(slash + 1, strlen(slash + 1));
}
