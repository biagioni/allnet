libincludes = \
	lib/app_util.h \
	lib/dcache.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/util.h

tracelibincludes = ai.h

keydlibincludes = \
	${libincludes} \
	cipher.h \
	keys.h \
	config.h \
	mapchar.h

includes = \
	../mgmt.h \
	../packet.h

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = trace keyd
trace_SOURCES = trace.c ${includes} ${tracelibincludes}
keyd_SOURCES = keyd.c ${includes} ${keydlibincludes}

install-exec-hook:
	$(LN_S) $(DESTDIR)$(bindir)trace $(DESTDIR)$(bindir)traced
