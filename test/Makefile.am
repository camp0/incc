python_PYTHON = test01.py testrunner.py

BUILT_SOURCES = $(srcdir)/incc_test_wrap.c

PYTHON_INCLUDES = -I/usr/include -I. -I.. -I../.. "`pkg-config --cflags glib-2.0 dbus-1 libpcre`"

CLEANFILES = $(srcdir)/incc_test_wrap.c $(srcdir)/_incc_test.so *.pyc incc_test.py

MAINTAINERCLEANFILES = \
	$(srcdir)/incc_test_wrap.c \
	$(srcdir)/Makefile.in \
	`rm -rf $(srcdir)/build `

$(srcdir)/incc_test_wrap.c: incc_test.i
	$(SWIG) -python incc_test.i
	$(PYTHON) setup.py build_ext --inplace -DHAVE_CONFIG_H

EXTRA_DIST =    README testall.sh incc_test.i setup.py

TESTS =		testall.sh

