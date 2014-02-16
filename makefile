LIBINCLUDES=lib/pipemsg.h lib/util.h lib/log.h lib/priority.h lib/config.h lib/table.h lib/dcache.h lib/sha.h lib/ai.h
INCLUDES= packet.h social.h record.h track.h listen.h ${LIBINCLUDES}

LIB=lib/pipemsg.c lib/util.c lib/log.c lib/priority.c lib/config.c lib/table.c lib/dcache.c lib/sha.c lib/ai.c
AD_LINK=social.c record.c track.c ${LIB}

all: bin/ad bin/alocal bin/aip bin/acache bin/astart bin/abc.nosudo bin/abc \
	bin/traced bin/allnet-subscribe

clean:
	/bin/rm -f ad alocal aip acache astart abc.nosudo abc

bin/traced: mgmt/trace.c ${LIBINCLUDES} ${LIB}
	cd ./mgmt && make

bin/allnet-subscribe: ahra/subscribe.c ${LIBINCLUDES} ${LIB}
	cd ./ahra && make

bin/abc: bin/abc.nosudo
	/bin/rm -f bin/abc
	cp bin/abc.nosudo bin/abc
	sudo chown root:root bin/abc
	sudo chmod u+s bin/abc

bin/ad: ad.c ${AD_LINK} ${INCLUDES}
	gcc -g -o bin/ad ad.c ${AD_LINK}

bin/abc.nosudo: abc.c mgmt.h lib/sha.h lib/pqueue.h lib/pqueue.c ${LIB} ${INCLUDES}
	gcc -g -o bin/abc.nosudo abc.c lib/pqueue.c ${LIB}
	echo run \'sudo make abc\' if you are going to run on wireless

bin/alocal: alocal.c mgmt.h listen.c ${LIB} ${INCLUDES}
	gcc -g -o bin/alocal alocal.c listen.c ${LIB} -lpthread

bin/aip: aip.c mgmt.h listen.c ${LIB} ${INCLUDES}
	gcc -g -o bin/aip aip.c listen.c ${LIB} -lpthread

bin/acache: acache.c ${LIB} ${INCLUDES}
	gcc -g -o bin/acache acache.c ${LIB} -lcrypto

bin/astart: astart.c ${LIB} ${INCLUDES}
	gcc -g -o bin/astart astart.c ${LIB}
	/bin/rm -f bin/astop
	/bin/ln bin/astart bin/astop

