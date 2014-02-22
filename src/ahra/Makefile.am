ad_includes = packet.h sha.h config.h pipemsg.h log.h util.h priority.h
includes = 
link = 

LDADD = ../lib/liballnet-$(ALLNET_API_VERSION).la
bin_PROGRAMS = allnet-generate allnet-subscribe
allnet-generate_SOURCES = generate.c ${link} ${includes} ${ad_includes}
allnet-generate_LDFLAGS = -lcrypto
allnet-subscribe_SOURCES = subscribe.c ${link} ${includes} ${ad_includes}
allnet-subscribe_LDFLAGS = -lcrypto
