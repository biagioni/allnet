AM_CFLAGS = -I$(ALLNET_SRCDIR)
libincludes = \
	lib/app_util.h \
	lib/cipher.h \
	lib/configfiles.h \
	lib/log.h \
	lib/media.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/util.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/allnet-radio \
	$(ALLNET_BINDIR)/allnet-broadcast \
	$(ALLNET_BINDIR)/xtime
__ALLNET_BINDIR__allnet_radio_SOURCES = allnet_radio.c ${libincludes}
__ALLNET_BINDIR__allnet_broadcast_SOURCES = broadcast.c ${libincludes}
__ALLNET_BINDIR__allnet_broadcast_LDFLAGS = -lpthread
__ALLNET_BINDIR__xtime_SOURCES = xtime.c ${libincludes}
__ALLNET_BINDIR__xtime_LDFLAGS = -lpthread
