#
# Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

dist_man_MANS =

$(MANS): doxyfile.stamp

$(top_builddir)/build-aux/doxyxml: $(top_srcdir)/build-aux/doxyxml.c
	$(MAKE) -C $(top_builddir)/build-aux doxyxml

doxyfile.stamp: Doxyfile $(top_srcdir)/libnozzle/libnozzle.h $(top_builddir)/build-aux/doxyxml $(top_srcdir)/build-aux/doxyxml.c
	$(DOXYGEN) Doxyfile
	$(top_builddir)/build-aux/doxyxml -m -P -o $(builddir) -s 3 -p @PACKAGE_NAME@ -H "Kronosnet Programmer's Manual" -d $(builddir)/xml/ libnozzle_8h.xml
	touch doxyfile.stamp

clean-local:
	rm -rf doxyfile.stamp xml *.3
