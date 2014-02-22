ad_includes = packet.h sha.h config.h pipemsg.h log.h util.h priority.h cipher.h
includes = 
link =

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la -lcrypto
bin_PROGRAMS = xtime
xtime_SOURCES = xtime.c ${link} ${includes} ${ad_includes}
