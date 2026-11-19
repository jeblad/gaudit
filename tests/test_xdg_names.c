/* SPDX-License-Identifier: GPL-3.0-only */
/* The names of the public share folder (xdg-public-names.c, generated):
 * each a plain folder name in valid UTF-8, each language and name once,
 * English first, and the known cases, current and old. */
#include "xdg-public-names.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* Valid UTF-8, no control characters, no '/', not "." or "..". */
static int plain_name(const char *s)
{
    if (*s == '\0' || strcmp(s, ".") == 0 || strcmp(s, "..") == 0 || strlen(s) > 255)
        return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0';) {
        if (*p < 0x20 || *p == 0x7f || *p == '/')
            return 0;
        int n = *p < 0x80 ? 0 : (*p & 0xe0) == 0xc0 ? 1 : (*p & 0xf0) == 0xe0 ? 2
              : (*p & 0xf8) == 0xf0 ? 3 : -1;
        if (n < 0 || (n == 1 && *p < 0xc2))
            return 0;
        p++;
        for (int i = 0; i < n; i++, p++)
            if ((*p & 0xc0) != 0x80)
                return 0;
    }
    return 1;
}

static const gaudit_xdg_public_name *find(const char *lang, const char *name)
{
    for (unsigned i = 0; i < gaudit_xdg_public_names_count; i++)
        if (strcmp(gaudit_xdg_public_names[i].lang, lang) == 0
            && strcmp(gaudit_xdg_public_names[i].name, name) == 0)
            return &gaudit_xdg_public_names[i];
    return NULL;
}

int main(void)
{
    CHECK(gaudit_xdg_public_names_count > 80);
    CHECK(strcmp(gaudit_xdg_public_names[0].name, "Public") == 0
          && gaudit_xdg_public_names[0].lang[0] == '\0');
    for (unsigned i = 0; i < gaudit_xdg_public_names_count; i++) {
        const gaudit_xdg_public_name *e = &gaudit_xdg_public_names[i];
        if (!plain_name(e->name))
            fprintf(stderr, "not a plain folder name: %s %s\n", e->lang, e->name), failures++;
        for (unsigned j = 0; j < i; j++)
            if (strcmp(gaudit_xdg_public_names[j].lang, e->lang) == 0
                && strcmp(gaudit_xdg_public_names[j].name, e->name) == 0)
                fprintf(stderr, "twice: %s %s\n", e->lang, e->name), failures++;
    }
    /* What the catalogs on a machine also say (checked on Ubuntu 26.10). */
    const gaudit_xdg_public_name *e;
    CHECK((e = find("nb", "Offentlig")) != NULL && e->current);
    CHECK((e = find("nn", "Offentleg")) != NULL && e->current);
    CHECK((e = find("da", "Offentligt")) != NULL && e->current);
    CHECK((e = find("sv", "Publikt")) != NULL && e->current);
    /* Old names, no longer in any catalog: why the table exists. */
    CHECK((e = find("sv", "Delat")) != NULL && !e->current);
    CHECK((e = find("fr", "Publique")) != NULL && !e->current);
    if (failures == 0)
        puts("xdg-names: all checks passed");
    return failures == 0 ? 0 : 1;
}
