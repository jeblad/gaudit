/* SPDX-License-Identifier: GPL-3.0-only */
/* Model: collected findings. Implemented in C++, exposed as a plain C API.
 *
 * Boundary rules (AGENTS.md):
 *  - opaque handles only; no C++ types visible here
 *  - no exceptions cross this boundary; every call returns a status
 *  - whoever allocates, frees (gaudit_model_new / gaudit_model_free)
 */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
#define GAUDIT_NOEXCEPT noexcept
extern "C" {
#else
#define GAUDIT_NOEXCEPT
#endif

typedef enum {
    GAUDIT_OK = 0,
    GAUDIT_ERR_INVALID,  /* bad argument */
    GAUDIT_ERR_NOMEM,
    GAUDIT_ERR_INTERNAL,
} gaudit_status;

/* Ordered by severity, so "worst" is the numerically largest. */
typedef enum {
    GAUDIT_VERDICT_OK = 0,
    GAUDIT_VERDICT_UNKNOWN,   /* check could not complete */
    GAUDIT_VERDICT_WARNING,
    GAUDIT_VERDICT_CRITICAL,
} gaudit_verdict;

typedef struct gaudit_model gaudit_model;

gaudit_status gaudit_model_new(gaudit_model **out) GAUDIT_NOEXCEPT;
void          gaudit_model_free(gaudit_model *model) GAUDIT_NOEXCEPT;

/* check_id is a language-neutral, stable identifier (e.g. "firewall.active").
 * One finding per check: adding one for a check_id already present
 * replaces its verdict, so a check run again never leaves its old result. */
gaudit_status gaudit_model_add_finding(gaudit_model *model,
                                       const char *check_id,
                                       gaudit_verdict verdict) GAUDIT_NOEXCEPT;

size_t         gaudit_model_count(const gaudit_model *model) GAUDIT_NOEXCEPT;

/* GAUDIT_VERDICT_UNKNOWN when the model is empty. */
gaudit_verdict gaudit_model_worst(const gaudit_model *model) GAUDIT_NOEXCEPT;

#ifdef __cplusplus
}
#endif
