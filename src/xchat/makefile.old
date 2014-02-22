LIB_INCLUDES= ../lib/pipemsg.h ../lib/priority.h ../lib/util.h ../lib/sha.h ../lib/config.h ../lib/log.h ../lib/app_util.h ../lib/cipher.h ../lib/keys.h ../lib/mapchar.h ../lib/ai.h
LIB_LINK= ../lib/pipemsg.c ../lib/priority.c ../lib/util.c ../lib/sha.c ../lib/config.c ../lib/log.c ../lib/app_util.c ../lib/cipher.c ../lib/keys.c ../lib/mapchar.c ../lib/ai.c
INCLUDES= chat.h cutil.h store.h retransmit.h xcommon.h
LINK=cutil.c store.c retransmit.c xcommon.c

all: chat xchgkey

chat: ../bin/xchatr ../bin/xchats ../bin/xchat_socket

xchgkey: ../bin/xkeys ../bin/xkeyr

../bin/xchatr: xchatr.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xchatr xchatr.c ${LINK} ${LIB_LINK} -lcrypto

../bin/xchats: xchats.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xchats xchats.c ${LINK} ${LIB_LINK} -lcrypto

../bin/xchat_socket: xchat_socket.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xchat_socket xchat_socket.c ${LINK} ${LIB_LINK} -lcrypto

../bin/xkeys: xkeys.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xkeys xkeys.c ${LINK} ${LIB_LINK} -lcrypto

../bin/xkeyr: xkeyr.c ${LINK} ${INCLUDES} ${LIB_INCLUDES} ${LIB_LINK}
	gcc -g -o ../bin/xkeyr xkeyr.c ${LINK} ${LIB_LINK} -lcrypto

