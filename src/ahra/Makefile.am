libincludes = \
	lib/cipher.h \
	lib/config.h \
	lib/keys.h \
	lib/log.h \
	lib/pipemsg.h \
	lib/priority.h \
	lib/sha.h \
	lib/app_util.h \
	lib/util.h

LDADD = $(top_srcdir)/src/lib/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = allnet-generate allnet-subscribe

allnet_generate_SOURCES = generate.c ${libincludes}
allnet_subscribe_SOURCES = subscribe.c ${libincludes} ../packet.h
