AM_CFLAGS = -I$(ALLNET_SRCDIR)
ad_includes = packet.h

libincludes = \
	lib/cipher.h \
	lib/config.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/util.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = xtime allnet-radio
xtime_SOURCES = xtime.c ${libincludes} ${ad_includes}
allnet_radio_SOURCES = allnet_radio.c ${libincludes}
