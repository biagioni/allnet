ad_includes = packet.h sha.h config.h pipemsg.h log.h util.h priority.h
includes = cipher.h
link = cipher.c

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = xtime
xtime_SOURCES = xtime.c ${link} ${includes} ${ad_includes}
xtime_LDFLAGS = -lcrypto
