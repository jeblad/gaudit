#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# The rule engine: the Private Files report on fixed input gives the
# expected lines, and rules that loop, allocate without end, touch files,
# evaluate code or do not even read give no report at all (exit 1).
# Usage: test_engine.sh <engine built with the test rules> <data dir>
set -u
engine=$1
data=$2
status=0

for n in 1 2 3 4 5 6; do
    if ! "$engine" report core.private-files < "$data/private-files-$n.in" > out.$$ 2>/dev/null; then
        echo "private-files-$n: no report" >&2; status=1
    elif ! cmp -s out.$$ "$data/private-files-$n.out"; then
        echo "private-files-$n: report differs:" >&2; diff "$data/private-files-$n.out" out.$$ >&2; status=1
    fi
done
rm -f out.$$

# Each must stop for its own reason, not by accident.
for case in loop:limit-exceeded alloc:limit-exceeded io:unbound-variable \
            eval:unbound-variable bad:read-error; do
    rule=${case%%:*}
    why=${case#*:}
    "$engine" report "$rule" < "$data/private-files-1.in" > out.$$ 2> err.$$
    code=$?
    if [ "$code" -ne 1 ] || [ -s out.$$ ] || ! grep -q "^$why" err.$$; then
        echo "rule $rule: exit $code, expected $why, got: $(head -c 200 err.$$)" >&2; status=1
    fi
done
rm -f out.$$ err.$$

# Once confined, the process itself can do none of it either.
if ! "$engine" selftest > out.$$ 2>&1; then
    echo "selftest:" >&2; cat out.$$ >&2; status=1
fi
rm -f out.$$

# The plugin id is a name, never a path.
for id in ../etc x/y .hidden ""; do
    if "$engine" report "$id" < /dev/null > /dev/null 2>&1 || [ $? -ne 2 ]; then
        echo "id '$id' was accepted" >&2; status=1
    fi
done
[ "$status" -eq 0 ] && echo "engine: all checks passed"
exit $status
