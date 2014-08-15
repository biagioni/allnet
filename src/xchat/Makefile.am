#SUBDIRS = test

AM_CFLAGS = -I$(ALLNET_SRCDIR) -I$(ALLNET_SRCDIR)/xtime -g
libincludes = \
    app_util.h \
    config.h \
    log.h \
    media.h \
    packet.h \
    pipemsg.h \
    priority.h \
    sha.h \
    util.h

includes = chat.h cutil.h store.h message.h retransmit.h xcommon.h
link = cutil.c store.c message.c retransmit.c xcommon.c

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/xchatr \
	$(ALLNET_BINDIR)/xchats \
	$(ALLNET_BINDIR)/xchat
__ALLNET_BINDIR__xchatr_SOURCES = xchatr.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchats_SOURCES = xchats.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchat_SOURCES = xchat_socket.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchat_LDFLAGS = -lpthread
# __ALLNET_BINDIR__xkeys_SOURCES = xkeys.c ${link} ${includes} ${libincludes}
# __ALLNET_BINDIR__xkeyr_SOURCES = xkeyr.c ${link} ${includes} ${libincludes}
