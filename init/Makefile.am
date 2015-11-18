#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

EXTRA_DIST		= kronosnetd.in kronosnetd.service.in \
			  kronosnetd.default

systemdconfdir		= $(SYSTEMDDIR)
systemdconf_DATA	= kronosnetd.service

initscriptdir		= $(INITDDIR)
initscript_SCRIPTS	= kronosnetd

%: %.in Makefile
	rm -f $@-t $@
	cat $< | sed \
		-e 's#@''SBINDIR@#$(sbindir)#g' \
		-e 's#@''SYSCONFDIR@#$(sysconfdir)#g' \
		-e 's#@''INITDDIR@#$(INITDDIR)#g' \
		-e 's#@''LOCALSTATEDIR@#$(localstatedir)#g' \
	    > $@-t
	mv $@-t $@

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(INITDEFAULTDIR)
	$(INSTALL) -m 644 $(srcdir)/kronosnetd.default $(DESTDIR)/$(INITDEFAULTDIR)/kronosnetd

uninstall-local:
	rm -f $(DESTDIR)/$(INITDEFAULTDIR)/kronosnetd
	rmdir $(DESTDIR)/$(INITDEFAULTDIR) || :;

all-local: $(initscript_SCRIPTS) $(systemdconf_DATA)

clean-local:
	rm -rf $(initscript_SCRIPTS) $(systemdconf_DATA)
