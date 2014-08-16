AM_CFLAGS = -I$(ALLNET_SRCDIR) -g
libincludes = \
	lib/cipher.h \
	lib/config.h \
	lib/keys.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/app_util.h \
	lib/util.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/allnet-generate \
	$(ALLNET_BINDIR)/allnet-subscribe
__ALLNET_BINDIR__allnet_generate_SOURCES = generate.c ${libincludes}
__ALLNET_BINDIR__allnet_subscribe_SOURCES = subscribe.c ${libincludes} lib/packet.h lib/media.h
