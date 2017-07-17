AM_CFLAGS = -I$(ALLNET_SRCDIR)
libincludes = \
    app_util.h \
    configfiles.h \
    log.h \
    media.h \
    packet.h \
    pipemsg.h \
    priority.h \
    sha.h \
    util.h

includes = chat.h cutil.h store.h message.h retransmit.h xcommon.h gui_socket.h
link = cutil.c store.c message.c retransmit.c xcommon.c

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/xchatr \
	$(ALLNET_BINDIR)/xchats \
	$(ALLNET_BINDIR)/xt	\
	$(ALLNET_BINDIR)/xchat
__ALLNET_BINDIR__xchatr_SOURCES = xchatr.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchats_SOURCES = xchats.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchat_SOURCES = gui_socket.c gui_respond.c gui_callback.c \
        gui_start_java.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xt_SOURCES = xchat_term.c ${link} ${includes} ${libincludes}
__ALLNET_BINDIR__xchatr_LDFLAGS = -lpthread
__ALLNET_BINDIR__xchats_LDFLAGS = -lpthread
__ALLNET_BINDIR__xchat_LDFLAGS = -lpthread
__ALLNET_BINDIR__xt_LDFLAGS = -lpthread
