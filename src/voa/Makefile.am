AM_CFLAGS = -I$(ALLNET_SRCDIR)
libincludes = \
	app_util.h \
	config.h \
	log.h \
	packet.h \
	pipemsg.h \
	priority.h \
	sha.h \
	util.h

includes =
link =
libs = ${gstreamer_LIBS}

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = voa
voa_SOURCES = voa.c ${link} ${includes} ${libincludes}
voa_CFLAGS = -I$(ALLNET_SRCDIR) ${gstreamer_CFLAGS}
voa_LDFLAGS = ${libs}
#bin_PROGRAMS = $(ALLNET_BINDIR)/voa
#__ALLNET_BINDIR__voa_SOURCES = voa.c ${link} ${includes} ${libincludes}
#__ALLNET_BINDIR__voa_CFLAGS = ${gstreamer_CFLAGS}
#__ALLNET_BINDIR__voa_LDFLAGS = ${libs}
