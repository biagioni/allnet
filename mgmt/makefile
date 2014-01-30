LIBINCLUDES=../lib/pipemsg.h ../lib/priority.h ../lib/log.h ../lib/util.h ../lib/app_util.h
INCLUDES= ../mgmt.h ../packet.h

LIB=../lib/pipemsg.c ../lib/priority.c ../lib/log.c ../lib/util.c ../lib/app_util.c
AD_LINK=

all: ../bin/trace

../bin/trace: trace.c ${INCLUDES} ${LIBINCLUDES} ${LIB}
	gcc -g -o ../bin/trace trace.c ${LIB}
