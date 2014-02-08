ad_includes = packet.h sha.h config.h pipemsg.h log.h util.h priority.h
ad_link = sha.c config.c pipemsg.c log.c util.c
includes = cipher.h
link = cipher.c

bin_PROGRAMS = xtime
xtime_SOURCES = xtime.c ${link} ${includes} ${ad_includes} ${ad_link}
xtime_LDFLAGS = -lcrypto
