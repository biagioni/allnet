libincludes = \
	abc.h \
	ai.h \
	app_util.h \
	cipher.h \
	configfiles.h \
	crypt_sel.h \
	dcache.h \
	dh.h \
	keys.h \
	allnet_log.h \
	mapchar.h \
	media.h \
	mgmt.h \
	packet.h \
        pcache.h \
	priority.h \
        record.h \
	routing.h \
	sha.h \
        social.h \
	sockets.h \
	stream.h \
	table.h \
	trace_util.h \
        track.h \
	util.h \
	wp_aes.h \
	wp_arith.h \
	wp_rsa.h

libsrc = \
        abc.c \
        adht.c \
	ai.c \
	app_util.c \
	cipher.c \
	configfiles.c \
	crypt_sel.c \
	dcache.c \
	dh.c \
	keys.c \
	allnet_log.c \
	mapchar.c \
        pcache.c \
	priority.c \
	record.c \
	routing.c \
	sha.c \
        social.c \
	sockets.c \
	stream.c \
	table.c \
	trace_util.c \
	track.c \
	util.c \
	wp_arith.c

# only included if ! HAVE_OPENSSL
#	asn1.c \
#	wp_aes.c \
#	wp_arith.c \
#	wp_rsa.c

DEPS_LIBS = ${openssl_LIBS} -lpthread

if !HAVE_OPENSSL
libincludes += ${wpincludes}
# libsrc += asn1.c wp_aes.c wp_arith.c wp_rsa.c
libsrc += asn1.c wp_aes.c wp_rsa.c
endif

lib_LTLIBRARIES = liballnet-@ALLNET_API_VERSION@.la
pkginclude_HEADERS = $(libincludes)
liballnet_@ALLNET_API_VERSION@_la_LIBADD = $(DEPS_LIBS)
liballnet_@ALLNET_API_VERSION@_la_SOURCES = $(libsrc) $(libincludes)
liballnet_@ALLNET_API_VERSION@_la_LDFLAGS = -version-info @LDVERSION@ $(ALLNET_LT_LDFLAGS)
