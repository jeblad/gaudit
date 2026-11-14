/* SPDX-License-Identifier: GPL-3.0-only */
/* The engine's own seccomp filter, on top of the shared deny list: once
 * Guile has loaded what it needs, the process can no longer open files,
 * change the filesystem, create any socket (so no D-Bus and no network),
 * start a program or a process. Threads stay possible (Guile's collector
 * uses them). Denied calls fail with EPERM (clone3 with ENOSYS, so the C
 * library falls back to clone, whose flags can be checked). */
#pragma once

/* 0 on success; the caller must not run a rule otherwise. */
int gaudit_engine_confine(void);

/* Tries what the filter forbids and prints one line per attempt
 * ("denied ..." or "ALLOWED ..."). 0 when everything was denied. */
int gaudit_engine_selftest(void);
