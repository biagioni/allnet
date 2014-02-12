SUBDIRS = lib mgmt xchat xtime

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

LDADD = lib/liballnet-$(ALLNET_API_VERSION).la
AD_LINK = social.c record.c track.c ai.c
bin_PROGRAMS = ad alocal aip acache astart abc
ad_SOURCES = ad.c ${AD_LINK} ${includes}
abc_SOURCES = abc.c mgmt.h ai.c lib/sha.h lib/pqueue.h ${includes}
alocal_SOURCES = alocal.c mgmt.h listen.c ai.c ${includes}
alocal_LDFLAGS = -lpthread
aip_SOURCES = aip.c mgmt.h listen.c ai.c ${includes}
aip_LDFLAGS = -lpthread
acache_SOURCES = acache.c ai.c ${includes}
acache_LDFLAGS = -lcrypto
astart_SOURCES = astart.c ai.c ${includes}

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		$(LN_S) astart astop
	cp abc abc.nosudo && \
		chown root:root abc && \
		chmod u+s abc
