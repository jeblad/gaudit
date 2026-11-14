# SPDX-License-Identifier: GPL-3.0-only
# The built-in plugins, one folder each. A plugin's code is grouped by the
# process it runs in, and each folder adds its sources to that process's
# target, so nothing of a plugin runs anywhere else:
#   plugin.c, *.c  the GUI (description, presentation)
#   helper/        the privileged helper (root, sandboxed per check)
#   backend/       the unprivileged probes and collectors
# Shared code (protocol, runner, generic pages) stays where it is. Until
# the plugin description format and the rule engine exist, this is how
# they are kept apart, so moving to them goes one folder at a time.
add_subdirectory(firewall)
add_subdirectory(updates)
add_subdirectory(private-files)
