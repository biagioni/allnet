#!/bin/sh
if [ -z "$AUTOMAKE" ]; then
    AUTOMAKE="automake";
fi;
AUTOMAKE="$AUTOMAKE --foreign" autoreconf -vfi
