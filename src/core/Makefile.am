AUTOMAKE_OPTIONS = gnu

lib_LTLIBRARIES = libincc.la

INCLUDES =	`pkg-config --cflags dbus-1 glib-2.0 libpcre libssl` \
                -I../utils/ \
		-I../bus/ 

BUILT_SOURCES = $(srcdir)/incc_wrap.c

libincc_la_SOURCES =	system.c privatecallbacks.c flowpool.c \
			connection.c packetdecoder.c signature.c protocol.c \
			packet.c detection.c payload.c incc.c 

noinst_HEADERS =	flowpool.h connection.h incc.h signature.h detection.h protocol.h \
			packetdecoder.h packetcontext.h genericflow.h privatecallbacks.h \
			system.h payload.h packet.h 

libincc_la_LIBADD = ../bus/libinccbus.la $(DEPS_LIBS) 
libincc_la_LDFLAGS = -version-info 0:0:0 $(DEPS_LIBS) `pkg-config --libs glib-2.0 dbus-1 libpcre libssl`
libincc_la_CPPFLAGS = -I$(PYTHON_CPPFLAGS) $(DEPS_CFLAGS)

PYTHON_INCLUDES = -I/usr/include -I. -I.. -I../.. "`pkg-config --cflags glib-2.0 dbus-1 libpcre libssl`" 

python_PYTHON = daemon.py

#bin_PROGRAMS = incc 

#incc_SOURCES = main.c 
#incc_LDFLAGS = $(DEPS_LIBS) -lincc -lpcap -lssl 
#incc_LDADD = -lincc $(DEPS_LIBS) -lssl

EXTRA_DIST = incc.i setup.py log4crc

CLEANFILES = $(srcdir)/incc_wrap.c $(srcdir)/_incc.so *.pyc incc.py 

MAINTAINERCLEANFILES = \
	$(srcdir)/incc_wrap.c \
	$(srcdir)/Makefile.in \
	`rm -rf $(srcdir)/build `

$(srcdir)/incc_wrap.c: incc.i
	$(SWIG) -python incc.i
#	$(PYTHON) setup.py build_ext --inplace 
	$(PYTHON) setup.py build_ext --inplace -DHAVE_CONFIG_H

