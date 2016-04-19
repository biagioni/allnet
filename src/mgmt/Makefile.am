AM_CFLAGS = -I$(ALLNET_SRCDIR)
libincludes = \
	lib/ai.h \
	lib/app_util.h \
	lib/dcache.h \
	lib/log.h \
	lib/media.h \
	lib/mgmt.h \
	lib/packet.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/trace_util.h \
	lib/util.h

keydlibincludes = \
	${libincludes} \
	lib/cipher.h \
	lib/keys.h \
	lib/configfiles.h \
	lib/mapchar.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/trace \
	$(ALLNET_BINDIR)/allnet-sniffer
__ALLNET_BINDIR__trace_SOURCES = trace.c ${libincludes}
__ALLNET_BINDIR__allnet_sniffer_SOURCES = sniffer.c ${libincludes} lib/ai.h

# Hooks to link traced to trace. Uncomment when not separately recompiled above.
# install-exec-hook:
# 	cd $(DESTDIR)$(bindir) && rm -f traced && $(LN_S) trace traced
#
# uninstall-hook:
# 	rm -f $(DESTDIR)$(bindir)/traced
