AM_CFLAGS = -I$(ALLNET_SRCDIR) -g
libincludes = \
	lib/app_util.h \
	lib/dcache.h \
	lib/log.h \
	lib/media.h \
	lib/mgmt.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/util.h

keydlibincludes = \
	${libincludes} \
	lib/cipher.h \
	lib/keys.h \
	lib/config.h \
	lib/mapchar.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/trace \
	$(ALLNET_BINDIR)/traced \
	$(ALLNET_BINDIR)/keyd
__ALLNET_BINDIR__trace_SOURCES = trace.c ${libincludes} lib/ai.h
__ALLNET_BINDIR__traced_SOURCES = trace.c ${libincludes} lib/ai.h
__ALLNET_BINDIR__keyd_SOURCES = keyd.c ${keydlibincludes}

# Hooks to link traced to trace. Uncomment when not separately recompiled above.
# install-exec-hook:
# 	cd $(DESTDIR)$(bindir) && rm -f traced && $(LN_S) trace traced
#
# uninstall-hook:
# 	rm -f $(DESTDIR)$(bindir)/traced
