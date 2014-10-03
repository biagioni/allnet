AM_CFLAGS = -g

libincludes = \
	ai.h \
	app_util.h \
	cipher.h \
	config.h \
	crypt_sel.h \
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
	stream.h \
	table.h \
	util.h

wpincludes = \
	wp_aes.h \
	wp_arith.h \
	wp_rsa.h

libsrc = \
	ai.c \
	app_util.c \
	cipher.c \
	config.c \
	crypt_sel.c \
	dcache.c \
	keys.c \
	log.c \
	mapchar.c \
	pipemsg.c \
	pqueue.c \
	priority.c \
	sha.c \
	stream.c \
	table.c \
	util.c

wpsrc = \
	asn1.c \
	wp_aes.c \
	wp_arith.c \
	wp_rsa.c

DEPS_LIBS = ${openssl_LIBS}

if ! HAVE_OPENSSL
libincludes += wpincludes
libsrc += wpsrc
endif

lib_LTLIBRARIES = liballnet-3.1.la
pkginclude_HEADERS = $(libincludes)
liballnet_3_1_la_LIBADD = $(DEPS_LIBS)
liballnet_3_1_la_CFLAGS = $(openssl_CFLAGS)
liballnet_3_1_la_SOURCES = $(libsrc) $(libincludes)
liballnet_3_1_la_LDFLAGS = -version-info 3:1:0 $(ALLNET_LT_LDFLAGS)
