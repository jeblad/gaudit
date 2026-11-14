/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "report" mode (see report.c). */
#pragma once

/* 0: the report was written to stdout; 1: none; 2: bad plugin id. */
int gaudit_orchestrator_report(const char *plugin_id);
