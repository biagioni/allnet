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

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = trace
trace_SOURCES = trace.c ../ai.c ${includes} ${libincludes}

install-exec-hook:
	$(LN_S) $(DESTDIR)$(bindir)trace $(DESTDIR)$(bindir)traced
