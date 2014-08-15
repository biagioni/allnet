AM_CFLAGS = -g

libincludes = \
	ai.h \
	app_util.h \
	cipher.h \
	config.h \
	dcache.h \
	keys.h \
	log.h \
	mapchar.h \
	media.h \
	mgmt.h \
	packet.h \
	pipemsg.h \
	pqueue.h \
	priority.h \
	sha.h \
	table.h \
	util.h

libsrc = \
	ai.c \
	app_util.c \
	cipher.c \
	config.c \
	dcache.c \
	keys.c \
	log.c \
	mapchar.c \
	pipemsg.c \
	pqueue.c \
	priority.c \
	sha.c \
	table.c \
	util.c

DEPS_LIBS = -lcrypto

lib_LTLIBRARIES = liballnet-0.3.la
pkginclude_HEADERS = $(libincludes)
liballnet_0_3_la_LIBADD = $(DEPS_LIBS)
liballnet_0_3_la_SOURCES = $(libsrc) $(libincludes)
liballnet_0_3_la_LDFLAGS = -version-info 0:3:0 $(ALLNET_LT_LDFLAGS)
