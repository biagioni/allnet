libincludes = \
    app_util.h \
	config.h \
	dcache.h \
	log.h \
	pipemsg.h \
	priority.h \
	sha.h \
	table.h \
	util.h

libsrc = \
    app_util.c \
	config.c \
	dcache.c \
	log.c \
	pipemsg.c \
	priority.c \
	sha.c \
	table.c \
	util.c

# noinst_LTLIBRARIES = liballnet-0.3.la
lib_LTLIBRARIES = liballnet-0.3.la
# liballnet_0_3_la_LIBADD = $(DEPS_LIBS) # no dependencies
liballnet_0_3_la_SOURCES = $(libsrc) $(libincludes)
liballnet_0_3_la_LDFLAGS = -version-info 0:3:0 $(ALLNET_LT_LDFLAGS)
