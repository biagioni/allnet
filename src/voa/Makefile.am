AM_CFLAGS = -I$(ALLNET_SRCDIR) # Overridden by custom __ALLNET_BINDIR__foo_CFLAGS
libincludes = \
	app_util.h \
	cipher.h \
	configfiles.h \
	crypt_sel.h \
	keys.h \
	log.h \
	media.h \
	packet.h \
	pipemsg.h \
	priority.h \
	stream.h \
	util.h

if USE_VOICE_OVER_ALLNET
bins = $(ALLNET_BINDIR)/voa
endif

includes =
link =
libs = ${gstreamer_LIBS}

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = ${bins}
__ALLNET_BINDIR__voa_SOURCES = voa.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__voa_CFLAGS = -I$(ALLNET_SRCDIR) ${gstreamer_CFLAGS}
__ALLNET_BINDIR__voa_LDFLAGS = ${libs}
