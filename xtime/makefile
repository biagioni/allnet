AD_INCLUDES= packet.h sha.h config.h pipemsg.h log.h util.h priority.h
AD_LINK= sha.c config.c pipemsg.c log.c util.c
INCLUDES= cipher.h
LINK=cipher.c

all: xtime

xtime: xtime.c ${LINK} ${INCLUDES} ${AD_INCLUDES} ${AD_LINK}
	gcc -g -o xtime xtime.c ${LINK} ${AD_LINK} -lcrypto

