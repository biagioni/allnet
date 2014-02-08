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

lib = \
	../lib/app_util.c \
	../lib/dcache.c \
	../lib/log.c \
	../lib/pipemsg.c \
	../lib/priority.c \
	../lib/util.c

bin_PROGRAMS = trace
trace_SOURCES = trace.c ../ai.c ${includes} ${libincludes} ${lib}

install-exec-hook:
	cp $(DESTDIR)$(bindir)trace $(DESTDIR)$(bindir)traced
