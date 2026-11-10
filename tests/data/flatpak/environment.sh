#!/bin/sh
# apps is 1 only if nothing leaked from the caller environment.
if [ -z "$GAUDIT_TEST_LEAK" ] && [ -n "$HOME" ]; then n=1; else n=0; fi
echo "(flatpak (apps $n) (eol-apps 0) (eol-unused 0) (eol-pinned 0))"
