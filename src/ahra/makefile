LIBINCLUDES=../lib/keys.h ../lib/pipemsg.h ../lib/util.h ../lib/log.h \
	../lib/priority.h ../lib/config.h ../lib/sha.h ../lib/ai.h \
	../lib/mapchar.h ../lib/cipher.h
INCLUDES=../lib/app_util.h

LIB=../lib/keys.c ../lib/pipemsg.c ../lib/util.c ../lib/log.c \
	../lib/priority.c ../lib/config.c ../lib/sha.c ../lib/ai.c \
	../lib/mapchar.c ../lib/cipher.c -lcrypto
LINK=../lib/app_util.c

all: ../bin/allnet-generate ../bin/allnet-subscribe

../bin/allnet-generate: generate.c ${INCLUDES} ${LIBINCLUDES} ${LIB} ${LINK}
	gcc -g -o ../bin/allnet-generate generate.c ${LIB} ${LINK}

../bin/allnet-subscribe: subscribe.c ${INCLUDES} ${LIBINCLUDES} ${LIB} ${LINK}
	gcc -g -o ../bin/allnet-subscribe subscribe.c ${LIB} ${LINK}
