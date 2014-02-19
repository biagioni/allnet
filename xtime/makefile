LIB_INCLUDES=../packet.h ../lib/sha.h ../lib/config.h ../lib/pipemsg.h ../lib/log.h ../lib/util.h ../lib/priority.h ../lib/cipher.h ../lib/keys.h ../lib/mapchar.h ../lib/app_util.h
LIB_LINK=../lib/sha.c ../lib/config.c ../lib/pipemsg.c ../lib/log.c ../lib/util.c ../lib/ai.c ../lib/cipher.c ../lib/keys.c ../lib/mapchar.c ../lib/app_util.c
INCLUDES=
LINK=

all: ../bin/xtime ../bin/allnet-radio

../bin/xtime: xtime.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xtime xtime.c ${LINK} ${LIB_LINK} -lcrypto

../bin/allnet-radio: allnet_radio.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/allnet-radio allnet_radio.c ${LINK} ${LIB_LINK} -lcrypto
