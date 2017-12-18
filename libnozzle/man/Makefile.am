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

update-man-pages: doxyfile.stamp

doxyfile.stamp: Doxyfile
if MANPAGEUPDATES
	$(DOXYGEN) Doxyfile
	$(DOXY2MAN) -o $(abs_srcdir) -s 3 --short-pkg @PACKAGE_NAME@ --pkg "Kronosnet Programmer's Manual" $(builddir)/xml/libnozzle_8h.xml
else
	@echo this system does not have doxy2man or doxygen installed. Unable to update man pages automatically.
endif
	touch doxyfile.stamp

clean-local:
	rm -rf doxyfile.stamp xml
