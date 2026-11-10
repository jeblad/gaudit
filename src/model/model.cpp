/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/model.h"

#include <new>
#include <string>
#include <vector>

struct gaudit_model {
    struct finding {
        std::string check_id;
        gaudit_verdict verdict;
    };
    std::vector<finding> findings;
};

namespace {

bool valid_verdict(gaudit_verdict v)
{
    return v >= GAUDIT_VERDICT_OK && v <= GAUDIT_VERDICT_CRITICAL;
}

} // namespace

extern "C" gaudit_status gaudit_model_new(gaudit_model **out) noexcept
{
    if (out == nullptr)
        return GAUDIT_ERR_INVALID;
    *out = new (std::nothrow) gaudit_model{};
    return *out ? GAUDIT_OK : GAUDIT_ERR_NOMEM;
}

extern "C" void gaudit_model_free(gaudit_model *model) noexcept
{
    delete model;
}

extern "C" gaudit_status gaudit_model_add_finding(gaudit_model *model,
                                                  const char *check_id,
                                                  gaudit_verdict verdict) noexcept
{
    if (model == nullptr || check_id == nullptr || *check_id == '\0'
        || !valid_verdict(verdict))
        return GAUDIT_ERR_INVALID;
    try {
        /* One finding per check: a later result replaces the earlier. */
        for (auto &f : model->findings)
            if (f.check_id == check_id) {
                f.verdict = verdict;
                return GAUDIT_OK;
            }
        model->findings.push_back({check_id, verdict});
        return GAUDIT_OK;
    } catch (const std::bad_alloc &) {
        return GAUDIT_ERR_NOMEM;
    } catch (...) {
        return GAUDIT_ERR_INTERNAL;
    }
}

extern "C" size_t gaudit_model_count(const gaudit_model *model) noexcept
{
    return model ? model->findings.size() : 0;
}

extern "C" gaudit_verdict gaudit_model_worst(const gaudit_model *model) noexcept
{
    if (model == nullptr || model->findings.empty())
        return GAUDIT_VERDICT_UNKNOWN;
    gaudit_verdict worst = GAUDIT_VERDICT_OK;
    for (const auto &f : model->findings)
        if (f.verdict > worst)
            worst = f.verdict;
    return worst;
}

extern "C" gaudit_verdict gaudit_model_summary(const gaudit_model *model) noexcept
{
    if (model == nullptr || model->findings.empty())
        return GAUDIT_VERDICT_UNKNOWN;
    for (const auto &f : model->findings)
        if (f.verdict == GAUDIT_VERDICT_UNKNOWN)
            return GAUDIT_VERDICT_UNKNOWN;
    return gaudit_model_worst(model);
}
