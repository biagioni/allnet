AD_INCLUDES= pipemsg.h priority.h util.h sha.h config.h log.h
AD_LINK= pipemsg.c priority.c util.c sha.c config.c log.c
INCLUDES= chat.h cutil.h store.h cipher.h retransmit.h xcommon.h
LINK=cutil.c store.c cipher.c retransmit.c xcommon.c

all: chat xchgkey

chat: xchatr xchats xchat_socket

xchgkey: xkeys xkeyr

xchatr: xchatr.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xchatr xchatr.c ${LINK} ${AD_LINK} -lcrypto

xchats: xchats.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xchats xchats.c ${LINK} ${AD_LINK} -lcrypto

xchat_socket: xchat_socket.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xchat_socket xchat_socket.c ${LINK} ${AD_LINK} -lcrypto

xkeys: xkeys.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xkeys xkeys.c ${LINK} ${AD_LINK} -lcrypto

xkeyr: xkeyr.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xkeyr xkeyr.c ${LINK} ${AD_LINK} -lcrypto

