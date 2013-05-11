AUTOMAKE_OPTIONS = gnu

lib_LTLIBRARIES = libinccbus.la

INCLUDES =      -I../opcodes/ \
		`pkg-config --cflags dbus-1 glib-2.0` \
                -I../utils/ 

libinccbus_la_SOURCES =	inccdbus.c 
noinst_HEADERS =	inccdbus.h 

libinccbus_la_LIBADD = $(DEPS_LIBS)
libinccbus_la_LDFLAGS = -version-info 0:0:0 $(DEPS_LIBS) `pkg-config --libs glib-2.0 dbus-1` 
libinccbus_la_CPPFLAGS = $(DEPS_CFLAGS)

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile.in 

