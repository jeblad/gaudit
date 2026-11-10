/* SPDX-License-Identifier: GPL-3.0-only */
/* Probe library internal. */
#pragma once

#include <stddef.h>

/* text as a quoted string for the pipe protocols: \" and \\ escaped,
 * other non-printable bytes replaced, so the receiving parser always
 * accepts it. 0 on success, -1 if it does not fit. */
int gaudit_probe_quote(char *out, size_t len, const char *text);
