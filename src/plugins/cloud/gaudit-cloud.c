/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "cloud.h"
#include "gaudit-cloud.h"

gboolean gaudit_cloud_line_ok(const char *line, gboolean *last)
{
    int kind = gaudit_cloud_parse_line(line, NULL, NULL);
    *last = kind == 2;
    return kind > 0;
}
