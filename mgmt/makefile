LIBINCLUDES=../lib/pipemsg.h ../lib/priority.h ../lib/log.h ../lib/util.h \
	    ../lib/dcache.h ../lib/app_util.h ../lib/ai.h
INCLUDES= ../mgmt.h ../packet.h

LIB=../lib/pipemsg.c ../lib/priority.c ../lib/log.c ../lib/util.c \
    ../lib/dcache.c ../lib/app_util.c ../lib/ai.c

KEYD_INCLUDES=../lib/cipher.h ../lib/keys.h ../lib/config.h ../lib/sha.h \
	 ../lib/mapchar.h ${INCLUDES} ${LIBINCLUDES}

KEYD_LIB=../lib/cipher.c ../lib/keys.c ../lib/config.c ../lib/sha.c \
	 ../lib/mapchar.c ${LIB}

all: ../bin/trace ../bin/traced ../bin/keyd

../bin/trace: trace.c ${INCLUDES} ${LIBINCLUDES} ${LIB}
	gcc -g -o ../bin/trace trace.c ${LIB}

../bin/traced: ../bin/trace
	cp -f ../bin/trace ../bin/traced

../bin/keyd: keyd.c ${KEYD_INCLUDES} ${KEYD_LIB}
	gcc -g -o ../bin/keyd keyd.c ${KEYD_LIB} -lcrypto
