#!/bin/sh
if [ -z "$ACLOCAL" ]; then
	ACLOCAL="aclocal";
fi;
if [ -z "$AUTOMAKE" ]; then
	AUTOMAKE="automake";
fi;
if [ -e /usr/local/share/aclocal ]; then
	ACPREFIX="/usr/local/share/aclocal"
fi;
if [ -e /usr/share/aclocal ]; then
	ACPREFIX="/usr/share/aclocal"
fi;
ACLOCAL="$ACLOCAL -I $ACPREFIX" AUTOMAKE="$AUTOMAKE --foreign" autoreconf -vfi
