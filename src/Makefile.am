SUBDIRS = lib mgmt xchat xtime

# AM_CFLAGS = -g -std=c99 -O2
AM_CFLAGS = -g -O2
AM_LDFLAGS =

libincludes = \
	lib/ai.h \
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
	listen.h \
	packet.h \
	record.h \
	social.h \
	track.h

LDADD = lib/liballnet-$(ALLNET_API_VERSION).la -lcrypto
AD_LINK = social.c record.c track.c
bin_PROGRAMS = ad alocal aip acache astart abc
ad_SOURCES = ad.c ${AD_LINK} ${includes}
abc_SOURCES = abc.c mgmt.h ${includes}
alocal_SOURCES = alocal.c mgmt.h listen.c ${includes}
alocal_LDFLAGS = -lpthread
aip_SOURCES = aip.c mgmt.h listen.c ${includes}
aip_LDFLAGS = -lpthread
acache_SOURCES = acache.c ${includes}
astart_SOURCES = astart.c ${includes}

install-exec-hook: 
	cd $(DESTDIR)$(bindir) && \
		$(LN_S) astart astop
	cp abc abc.nosudo && \
		chown root:root abc && \
		chmod u+s abc
