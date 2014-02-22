#SUBDIRS = test

AM_CPPFLAGS = -I../xtime -I../lib
ad_includes = app_util.h packet.h pipemsg.h priority.h util.h sha.h config.h log.h
includes = chat.h cutil.h store.h retransmit.h xcommon.h
link = cutil.c store.c retransmit.c xcommon.c

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la -lcrypto
bin_PROGRAMS = xchatr xchats xchat_socket xkeys xkeyr
xchatr_SOURCES = xchatr.c ${link} ${includes} ${ad_includes}
xchats_SOURCES = xchats.c ${link} ${includes} ${ad_includes}
xchat_socket_SOURCES = xchat_socket.c ${link} ${includes} ${ad_includes}
xkeys_SOURCES = xkeys.c ${link} ${includes} ${ad_includes}
xkeyr_SOURCES = xkeyr.c ${link} ${includes} ${ad_includes}
