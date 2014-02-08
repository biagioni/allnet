includes = \
    ../key.h \
    ../../v2/sha.h \
    ../../v2/util.h \
    ../../v2/config.h

bin_PROGRAMS = tkey
tkey_SOURCES = ${INCLUDES} ../key.c ../../v2/sha.c ../../v2/util.c ../../v2/config.c
tkey_LDFLAGS = -lcrypto
