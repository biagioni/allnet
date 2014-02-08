LIBINCLUDES=../lib/pipemsg.h ../lib/priority.h ../lib/log.h ../lib/util.h \
	    ../lib/dcache.h ../lib/app_util.h
INCLUDES= ../mgmt.h ../packet.h

LIB=../lib/pipemsg.c ../lib/priority.c ../lib/log.c ../lib/util.c \
    ../lib/dcache.c ../lib/app_util.c
AD_LINK=

all: ../bin/trace ../bin/traced

../bin/trace: trace.c ../ai.c ${INCLUDES} ${LIBINCLUDES} ${LIB}
	gcc -g -o ../bin/trace trace.c ../ai.c ${LIB}

../bin/traced: ../bin/trace
	cp ../bin/trace ../bin/traced
