# SPDX-License-Identifier: GPL-3.0-only
# Model (C++) behind a plain C API. See AGENTS.md, "Goals and platform".
add_library(gaudit_model STATIC model.cpp)
target_include_directories(gaudit_model PUBLIC include)
