MAINTAINERCLEANFILES	= Makefile.in

EXTRA_DIST		= kronosnetd.in kronosnetd.service.in

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

all-local: $(initscript_SCRIPTS) $(systemdconf_DATA)

clean-local:
	rm -rf $(initscript_SCRIPTS) $(systemdconf_DATA)
