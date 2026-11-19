/* SPDX-License-Identifier: GPL-3.0-only */
/* The built-in plugins' descriptions, one per folder under src/plugins/. */
#pragma once

#include "gaudit-task.h"

G_BEGIN_DECLS

extern const GauditTaskInfo gaudit_plugin_firewall;
extern const GauditTaskInfo gaudit_plugin_updates;
extern const GauditTaskInfo gaudit_plugin_private_files;
extern const GauditTaskInfo gaudit_plugin_shared_folder;
extern const GauditTaskInfo gaudit_plugin_cloud;

G_END_DECLS
