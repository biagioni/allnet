AUTOMAKE_OPTIONS = subdir-objects
libincludes = \
	../lib/app_util.h \
	../lib/dcache.h \
	../lib/log.h \
	../lib/pipemsg.h \
	../lib/priority.h \
	../lib/util.h

includes = \
	../mgmt.h \
	../packet.h

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la -lcrypto
bin_PROGRAMS = trace keyd
trace_SOURCES = trace.c ${includes} ${libincludes}
keyd_SOURCES = keyd.c ${includes} ${libincludes}

install-exec-hook:
	$(LN_S) $(DESTDIR)$(bindir)trace $(DESTDIR)$(bindir)traced
