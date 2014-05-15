#!/bin/sh
if [ -z "$ACLOCAL" ]; then
	ACLOCAL="aclocal";
fi;
if [ -z "$AUTOMAKE" ]; then
	AUTOMAKE="automake";
fi;
ACLOCAL="$ACLOCAL -I /usr/share/aclocal/" AUTOMAKE="$AUTOMAKE --foreign" autoreconf -vfi
