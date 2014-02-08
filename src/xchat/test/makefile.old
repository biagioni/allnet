INCLUDES= ../key.h ../../v2/sha.h ../../v2/util.h ../../v2/config.h

all: tkey

tkey: tkey.c ${INCLUDES} ../key.c ../../v2/sha.c ../../v2/util.c ../../v2/config.c
	gcc -g -o tkey tkey.c ../key.c ../../v2/sha.c ../../v2/util.c ../../v2/config.c -lcrypto

