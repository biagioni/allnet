SUBDIRS = lib ahra mgmt voa xchat gui xtime
AUTOMAKE_OPTIONS = subdir-objects

libincludes = \
	lib/ai.h \
	lib/configfiles.h \
	lib/dcache.h \
	lib/log.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/routing.h \
	lib/sha.h \
	lib/table.h \
	lib/util.h

includes = \
	${libincludes} \
	config.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/allnetd \
	$(ALLNET_BINDIR)/astop \
	$(ALLNET_BINDIR)/allnet-print-caches

__ALLNET_BINDIR__allnetd_SOURCES = astart.c \
				   ad.c \
				   atcpd.c \
				   mgmt/keyd.c \
				   ${includes}
__ALLNET_BINDIR__allnetd_LDFLAGS = -lpthread
__ALLNET_BINDIR__astop_SOURCES = ${__ALLNET_BINDIR__allnetd_SOURCES}
__ALLNET_BINDIR__astop_LDFLAGS = -lpthread
__ALLNET_BINDIR__allnet_print_caches_SOURCES = print_caches.c
__ALLNET_BINDIR__allnet_print_caches_LDFLAGS = -lpthread

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		rm -f astop && \
		$(LN_S) -f allnetd astop

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/astop && \
	rm -f $(DESTDIR)$(bindir)/allnetd
