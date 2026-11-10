/* SPDX-License-Identifier: GPL-3.0-only */
/* gaudit-orchestrator: runs as the user, started by the GUI for each status
 * refresh. It runs the Home status probes (which start their own
 * collectors), writes one line per result on stdout, and exits.
 *
 * The GUI treats this output as untrusted input: it is size limited and
 * parsed strictly (gaudit_probe_parse_all). Starting the privileged helper
 * and the rule engine comes later. */
#include "config.h"

#include "gaudit/backend.h"
#include "gaudit/probe.h"

#include <stdio.h>
#include <time.h>

int main(void)
{
    gaudit_probe_result results[GAUDIT_PROBE_COUNT];
    gaudit_probe_collect_ex(gaudit_pkg_backend_default(), gaudit_pkg_backend_expected(),
                            (int64_t)time(NULL), results);

    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        char line[1024];
        if (gaudit_probe_format(&results[k], line, sizeof line) != 0)
            return 1;
        if (fputs(line, stdout) == EOF)
            return 1;
    }
    return fflush(stdout) == 0 ? 0 : 1;
}
