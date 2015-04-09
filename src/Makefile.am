SUBDIRS = lib abc ahra mgmt voa xchat xtime xchat_ui
AUTOMAKE_OPTIONS = subdir-objects

libincludes = \
	lib/ai.h \
	lib/config.h \
	lib/dcache.h \
	lib/log.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/table.h \
	lib/util.h

includes = \
	${libincludes} \
	config.h \
	listen.h \
	record.h \
	social.h \
	track.h

adlink = social.c record.c track.c

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la \
        $(ALLNET_ABCDIR)/liballnet-abc-$(ALLNET_API_VERSION).la
# eventually, phase out astart
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/allnet \
	$(ALLNET_BINDIR)/astart \
	$(ALLNET_BINDIR)/astop

__ALLNET_BINDIR__astart_SOURCES = astart.c \
				  ad.c \
				  alocal.c \
				  listen.c \
				  aip.c \
				  adht.c \
				  routing.c \
				  acache.c \
				  hash.c \
				  record.c \
				  social.c \
				  track.c \
				  mgmt/trace.c \
				  mgmt/keyd.c \
				  ${includes}
__ALLNET_BINDIR__astart_LDFLAGS = -lpthread
__ALLNET_BINDIR__astop_SOURCES = ${__ALLNET_BINDIR__astart_SOURCES}
__ALLNET_BINDIR__astop_LDFLAGS = -lpthread
__ALLNET_BINDIR__allnet_SOURCES = ${__ALLNET_BINDIR__astart_SOURCES}
__ALLNET_BINDIR__allnet_LDFLAGS = -lpthread

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		rm -f astop && \
		$(LN_S) astart astop && \
		$(LN_S) astart allnet;

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/astop && \
	rm -f $(DESTDIR)$(bindir)/allnet
