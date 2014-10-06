AM_CFLAGS = -I$(ALLNET_SRCDIR) # not used on targets with *_CFLAGS set
libincludes = \
	lib/log.h \
	lib/mgmt.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/pqueue.h \
	lib/priority.h \
	lib/util.h

abcmodulesinc =
abcmoduleslibs =
abcmodules = \
	abc-ip.c \
	abc-ip.h \
	abc-wifi.c \
	abc-wifi.h \
	abc-iw.c \
	abc-iw.h

if USE_NETWORK_MANAGER
# conditionally enable NM and DBUS_*
abcmodules += abc-networkmanager.c abc-networkmanager.h
abcmodulesinc += -DUSE_NETWORK_MANAGER ${DBUS_CFLAGS}
abcmoduleslibs += ${DBUS_LIBS}
endif

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
# bin_PROGRAMS = $(ALLNET_BINDIR)/abc
lib_LTLIBRARIES = liballnet-abc-@ALLNET_API_VERSION@.la
liballnet_abc_@ALLNET_API_VERSION@_la_SOURCES = abc.c abc-iface.c abc-iface.h ${abcmodules} ${libincludes}
liballnet_abc_@ALLNET_API_VERSION@_la_CFLAGS = -DNO_MAIN_FUNCTION -I$(ALLNET_SRCDIR) ${abcmodulesinc}
liballnet_abc_@ALLNET_API_VERSION@_la_LDFLAGS = -version-info @LDVERSION@ $(ALLNET_LT_LDFLAGS) ${abcmoduleslibs}
liballnet_abc_@ALLNET_API_VERSION@_la_LIBADD = $(abcmodulelibs) $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
# __ALLNET_BINDIR__abc_SOURCES = abc.c abc-iface.c abc-iface.h ${abcmodules} ${libincludes}
# __ALLNET_BINDIR__abc_CFLAGS = -I$(ALLNET_SRCDIR) ${abcmodulesinc}
# __ALLNET_BINDIR__abc_LDFLAGS = ${abcmoduleslibs}
# 
# install-exec-hook: 
# 	cd $(DESTDIR)$(bindir) && \
# 	if [ "$$UID" -eq "0" ]; then \
# 		cp abc abc.nosudo && \
# 		chown root:root abc && \
# 		chmod u+s abc || true; \
# 	else \
# 		echo "Cannot set suid bit on abc. abc only requires root privileges when using iw."; \
# 	fi
# 
# uninstall-hook:
# 	rm -f $(DESTDIR)$(bindir)/abc.nosudo
