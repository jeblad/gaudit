# SPDX-License-Identifier: GPL-3.0-only
# Firewall (core.firewall): reads the nftables ruleset in the helper.
target_sources(gaudit PRIVATE plugin.c gaudit-firewall-text.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(gaudit_sandbox PRIVATE helper/nft.c)
target_include_directories(gaudit_sandbox PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/helper)
