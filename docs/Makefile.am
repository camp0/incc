#directory = $(top_srcdir)/docs/man/man3/

#dist_man_MANS = $(directory)/man_page_1.3 $(directory)/man_page_2.3
#$(directory)/man_page_1.3: doxyfile.stamp
#$(directory)/man_page_2.3: doxyfile.stamp

doxyfile.stamp:
	$(DOXYGEN) doxyfile
	echo Timestamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp 

MAINTAINERCLEANFILES = \
	$(srcdir)/doxyfile.stamp \
        $(srcdir)/Makefile.in 

all-local: doxyfile.stamp 
clean-local:
	rm -rf $(top_srcdir)/docs/mam html latex
