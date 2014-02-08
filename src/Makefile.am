SUBDIRS = mgmt xchat xtime
AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = -g -std=c99 -O2
AM_LDFLAGS =

libincludes = \
	lib/config.h \
	lib/dcache.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/table.h \
	lib/util.h

includes = \
	${libincludes} \
	ai.h \
	listen.h \
	packet.h \
	record.h \
	social.h \
	track.h

lib = \
	lib/config.c \
	lib/dcache.c \
	lib/log.c \
	lib/pipemsg.c \
	lib/priority.c \
	lib/sha.c \
	lib/table.c \
	lib/util.c

AD_LINK = social.c record.c track.c ai.c ${lib}
bin_PROGRAMS = ad alocal aip acache astart abc
ad_SOURCES = ad.c ${AD_LINK} ${includes}
abc_SOURCES = abc.c mgmt.h ai.c lib/sha.h lib/pqueue.h lib/pqueue.c ${lib} ${includes}
alocal_SOURCES = alocal.c mgmt.h listen.c ai.c ${lib} ${includes}
alocal_LDFLAGS = -lpthread
aip_SOURCES = aip.c mgmt.h listen.c ai.c ${lib} ${includes}
aip_LDFLAGS = -lpthread
acache_SOURCES = acache.c ai.c ${lib} ${includes}
acache_LDFLAGS = -lcrypto
astart_SOURCES = astart.c ai.c ${lib} ${includes}

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		$(LN_S) astart astop
	cp abc abc.nosudo && \
		sudo chown root:root abc && \
		sudo chmod u+s abc 
