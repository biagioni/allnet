#SUBDIRS = test

AM_CPPFLAGS = -I$(top_srcdir)/src/xtime -I$(top_srcdir)/src/lib
ad_includes = packet.h pipemsg.h priority.h util.h sha.h config.h log.h
ad_link = pipemsg.c priority.c util.c sha.c config.c log.c
includes = chat.h cutil.h store.h cipher.h retransmit.h xcommon.h
link = cutil.c store.c cipher.c retransmit.c xcommon.c

bin_PROGRAMS = xchatr xchats xchat_socket xkeys xkeyr
xchatr_SOURCES = xchatr.c ${link} ${includes} ${ad_includes} ${ad_link}
xchatr_LDFLAGS = -lcrypto
xchats_SOURCES = xchats.c ${link} ${includes} ${ad_includes} ${ad_link}
xchats_LDFLAGS = -lcrypto
xchat_socket_SOURCES = xchat_socket.c ${link} ${includes} ${ad_includes} ${ad_link}
xchat_socket_LDFLAGS = -lcrypto
xkeys_SOURCES = xkeys.c ${link} ${includes} ${ad_includes} ${ad_link}
xkeys_LDFLAGS = -lcrypto
xkeyr_SOURCES = xkeyr.c ${link} ${includes} ${ad_includes} ${ad_link}
xkeyr_LDFLAGS = -lcrypto
