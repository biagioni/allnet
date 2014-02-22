#SUBDIRS = test

AM_CPPFLAGS = -I$(ALLNET_SRCDIR) -I$(ALLNET_SRCDIR)/xtime
libincludes = \
    app_util.h \
    config.h \
    log.h \
    packet.h \
    pipemsg.h \
    priority.h \
    sha.h \
    util.h
includes = chat.h cutil.h store.h retransmit.h xcommon.h
link = cutil.c store.c retransmit.c xcommon.c

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = xchatr xchats xchat_socket xkeys xkeyr
xchatr_SOURCES = xchatr.c ${link} ${includes} ${libincludes}
xchats_SOURCES = xchats.c ${link} ${includes} ${libincludes}
xchat_socket_SOURCES = xchat_socket.c ${link} ${includes} ${libincludes}
xkeys_SOURCES = xkeys.c ${link} ${includes} ${libincludes}
xkeyr_SOURCES = xkeyr.c ${link} ${includes} ${libincludes}
