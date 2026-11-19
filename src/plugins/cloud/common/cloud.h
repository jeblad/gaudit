/* SPDX-License-Identifier: GPL-3.0-only */
/* The Cloud Services collection's lines, between orchestrator and GUI
 * ("gaudit-orchestrator cloud quick"), parsed strictly on the receiving
 * side. Facts only; what they mean is the rule's.
 *
 *   (cloud-folder (client "...") (service "...") (how N) (path "...") (name "...")
 *                 (encrypted 0|1) (gathered 0|1))                          one per finding
 *   (cloud-end (count N) (more 0|1) (gathering "...") (gatherings N) (rclone-unreadable 0|1))  last
 *
 * how: 0 the client's settings name the folder, 1 its default folder is
 * there, 2 installed only, 3 mounted, 4 set up without a folder of its own
 * (cloud-folders.h). path: "~/..." in the home folder, else absolute, ""
 * for none; the same for the gathering folder. */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char client[16];
    char service[16];
    int how;
    char path[256];
    char name[128];
    int encrypted, gathered;
} gaudit_cloud_line;

typedef struct {
    unsigned count, gatherings;
    int more, rclone_unreadable;
    char gathering[256];
} gaudit_cloud_end;

int gaudit_cloud_format_folder(const gaudit_cloud_line *f, char *buf, size_t len);
int gaudit_cloud_format_end(const gaudit_cloud_end *e, char *buf, size_t len);

/* 1 a folder line, 2 the end; -1 for anything else. f or e may be NULL. */
int gaudit_cloud_parse_line(const char *line, gaudit_cloud_line *f, gaudit_cloud_end *e);

#ifdef __cplusplus
}
#endif
