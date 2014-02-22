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
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/xtime \
	$(ALLNET_BINDIR)/allnet-radio
__ALLNET_BINDIR__xtime_SOURCES = xtime.c ${libincludes} ${ad_includes}
__ALLNET_BINDIR__allnet_radio_SOURCES = allnet_radio.c ${libincludes}
