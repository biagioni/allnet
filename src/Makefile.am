SUBDIRS = lib abc ahra mgmt xchat xtime xchat_ui
AM_CFLAGS = -g
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

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/ad \
	$(ALLNET_BINDIR)/alocal \
	$(ALLNET_BINDIR)/aip \
	$(ALLNET_BINDIR)/acache \
	$(ALLNET_BINDIR)/astart \
	$(ALLNET_BINDIR)/astop \
	$(ALLNET_BINDIR)/adht \
	$(ALLNET_BINDIR)/allnetx

__ALLNET_BINDIR__ad_SOURCES = ad.c ${adlink} ${includes}
__ALLNET_BINDIR__alocal_SOURCES = alocal.c listen.c ${includes} lib/mgmt.h
__ALLNET_BINDIR__alocal_LDFLAGS = -lpthread
__ALLNET_BINDIR__aip_SOURCES = aip.c listen.c routing.c ${includes} lib/mgmt.h
__ALLNET_BINDIR__aip_LDFLAGS = -lpthread
__ALLNET_BINDIR__adht_SOURCES = adht.c routing.c ${includes} lib/mgmt.h routing.h
__ALLNET_BINDIR__adht_LDFLAGS = -lpthread
__ALLNET_BINDIR__acache_SOURCES = acache.c ${includes}
__ALLNET_BINDIR__astart_SOURCES = astart.c ${includes}
__ALLNET_BINDIR__astop_SOURCES = astart.c ${includes}
__ALLNET_BINDIR__allnetx_SOURCES = allnetx.c ad.c alocal.c aip.c adht.c acache.c mgmt/trace.c mgmt/keyd.c listen.c routing.c ${adlink} ${includes} lib/mgmt.h routing.h
__ALLNET_BINDIR__allnetx_CPPFLAGS = -DNO_MAIN_FUNCTION
__ALLNET_BINDIR__allnetx_LDFLAGS = -lpthread
__ALLNET_BINDIR__allnetx_LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la abc/liballnet-abc-$(ALLNET_API_VERSION).la

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		rm -f astop && \
		$(LN_S) astart astop;

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/astop
