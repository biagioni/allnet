SUBDIRS = lib ahra mgmt xchat xtime xchat_ui
AM_CFLAGS = -g -O2

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

abcmodulesinc =
abcmoduleslibs =
abcmodules = \
    abc-wifi.c \
    abc-wifi.h \
    abc-iw.c \
    abc-iw.h

if USE_NETWORK_MANAGER
# conditionally enable NM and DBUS_*
abcmodules += abc-networkmanager.c abc-networkmanager.h lib/util.h
abcmodulesinc += -DUSE_NETWORK_MANAGER ${DBUS_CFLAGS}
abcmoduleslibs += ${DBUS_LIBS}
endif

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/ad \
	$(ALLNET_BINDIR)/alocal \
	$(ALLNET_BINDIR)/aip \
	$(ALLNET_BINDIR)/acache \
	$(ALLNET_BINDIR)/astart \
	$(ALLNET_BINDIR)/astop \
	$(ALLNET_BINDIR)/abc \
	$(ALLNET_BINDIR)/adht

__ALLNET_BINDIR__ad_SOURCES = ad.c ${adlink} ${includes}
__ALLNET_BINDIR__abc_SOURCES = abc.c abc-iface.h ${abcmodules} ${includes} lib/mgmt.h lib/pqueue.h
__ALLNET_BINDIR__abc_CFLAGS = ${abcmodulesinc}
__ALLNET_BINDIR__abc_LDFLAGS = ${abcmoduleslibs}
__ALLNET_BINDIR__alocal_SOURCES = alocal.c listen.c ${includes} lib/mgmt.h
__ALLNET_BINDIR__alocal_LDFLAGS = -lpthread
__ALLNET_BINDIR__aip_SOURCES = aip.c listen.c routing.c ${includes} lib/mgmt.h
__ALLNET_BINDIR__aip_LDFLAGS = -lpthread
__ALLNET_BINDIR__adht_SOURCES = adht.c routing.c ${includes} lib/mgmt.h routing.h
__ALLNET_BINDIR__adht_LDFLAGS = -lpthread
__ALLNET_BINDIR__acache_SOURCES = acache.c ${includes}
__ALLNET_BINDIR__astart_SOURCES = astart.c ${includes}
__ALLNET_BINDIR__astop_SOURCES = astart.c ${includes}

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		rm -f astop && \
		$(LN_S) astart astop; \
	if [ "$$UID" -eq "0" ]; then \
		cp abc abc.nosudo && \
		chown root:root abc && \
		chmod u+s abc || true; \
	else \
		echo "Cannot set suid bit on abc. abc requires root privileges."; \
	fi

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/abc.nosudo \
		  $(DESTDIR)$(bindir)/astop
