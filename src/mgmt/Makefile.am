AM_CFLAGS = -I$(ALLNET_SRCDIR)
libincludes = \
	lib/app_util.h \
	lib/dcache.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/util.h

tracelibincludes = lib/ai.h

keydlibincludes = \
	${libincludes} \
	cipher.h \
	keys.h \
	config.h \
	mapchar.h

includes = \
	mgmt.h \
	packet.h

LDADD = $(ALLNET_LIBDIR)/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = \
	$(ALLNET_BINDIR)/trace \
	$(ALLNET_BINDIR)/traced \
	$(ALLNET_BINDIR)/keyd
__ALLNET_BINDIR__trace_SOURCES = trace.c ${includes} ${tracelibincludes}
__ALLNET_BINDIR__traced_SOURCES = trace.c ${includes} ${tracelibincludes}
__ALLNET_BINDIR__keyd_SOURCES = keyd.c ${includes} ${keydlibincludes}

install-exec-hook:
	cd $(DESTDIR)$(bindir) && rm -f traced && $(LN_S) trace traced

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/traced
