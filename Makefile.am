#
# Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~ \
			  autoscan.log configure.scan test-driver \
			  m4/libtool.m4 m4/lt~obsolete.m4 m4/ltoptions.m4 \
			  m4/ltsugar.m4 m4/ltversion.m4

include $(top_srcdir)/build-aux/check.mk

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SPEC			= $(PACKAGE_NAME).spec

TARGZFILE		= $(PACKAGE_NAME)-$(VERSION).tar.gz

EXTRA_DIST		= autogen.sh .version \
			  NOTES_TO_PACKAGE_MAINTAINERS \
			  $(SPEC).in build-aux

SUBDIRS			= libnozzle libknet

if BUILD_MAN
SUBDIRS			+= man
endif

dist_doc_DATA		= \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence \
			  README

all-local: $(SPEC)

clean-local:
	rm -rf $(SPEC) cov*

distclean-local:
	rm -f $(PACKAGE_NAME)-*.tar.* $(PACKAGE_NAME)-*.sha256* tag-*

## make rpm/srpm section.

$(SPEC): $(SPEC).in .version config.status
	rm -f $@-t $@
	date="`LC_ALL=C $(UTC_DATE_AT)$(SOURCE_EPOCH) "+%a %b %d %Y"`" && \
	gvgver="`cd $(abs_srcdir); build-aux/git-version-gen --fallback $(VERSION) .tarball-version .gitarchivever`" && \
	if [ "$$gvgver" = "`echo $$gvgver | sed 's/-/./'`" ];then \
		rpmver="$$gvgver" && \
		alphatag="" && \
		dirty="" && \
		numcomm="0"; \
	else \
		gitver="`echo $$gvgver | sed 's/\(.*\)\./\1-/'`" && \
		rpmver=`echo $$gitver | sed 's/-.*//g'` && \
		alphatag=`echo $$gvgver | sed 's/[^-]*-\([^-]*\).*/\1/'` && \
		numcomm=`echo $$gitver | sed 's/[^-]*-\([^-]*\).*/\1/'` && \
		dirty="" && \
		if [ "`echo $$gitver | sed 's/^.*-dirty$$//g'`" = "" ];then \
			dirty="dirty"; \
		fi \
	fi && \
	if [ -n "$$dirty" ]; then dirty="dirty"; else dirty=""; fi && \
	if [ "$$numcomm" = "0" ]; then \
		sed \
			-e "s#@version@#$$rpmver#g" \
			-e "s#%glo.*alpha.*##g" \
			-e "s#%glo.*numcomm.*##g" \
			-e "s#@dirty@#$$dirty#g" \
			-e "s#@date@#$$date#g" \
		$(abs_srcdir)/$@.in > $@-t; \
	else \
		sed \
			-e "s#@version@#$$rpmver#g" \
			-e "s#@alphatag@#$$alphatag#g" \
			-e "s#@numcomm@#$$numcomm#g" \
			-e "s#@dirty@#$$dirty#g" \
			-e "s#@date@#$$date#g" \
		$(abs_srcdir)/$@.in > $@-t; \
	fi; \
	if [ -z "$$dirty" ]; then sed -i -e "s#%glo.*dirty.*##g" $@-t; fi
if BUILD_SCTP
	sed -i -e "s#@sctp@#bcond_without#g" $@-t
else
	sed -i -e "s#@sctp@#bcond_with#g" $@-t
endif
if BUILD_CRYPTO_NSS
	sed -i -e "s#@nss@#bcond_without#g" $@-t
else
	sed -i -e "s#@nss@#bcond_with#g" $@-t
endif
if BUILD_CRYPTO_OPENSSL
	sed -i -e "s#@openssl@#bcond_without#g" $@-t
else
	sed -i -e "s#@openssl@#bcond_with#g" $@-t
endif
if BUILD_CRYPTO_GCRYPT
	sed -i -e "s#@gcrypt@#bcond_without#g" $@-t
else
	sed -i -e "s#@gcrypt@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_ZLIB
	sed -i -e "s#@zlib@#bcond_without#g" $@-t
else
	sed -i -e "s#@zlib@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_LZ4
	sed -i -e "s#@lz4@#bcond_without#g" $@-t
else
	sed -i -e "s#@lz4@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_LZO2
	sed -i -e "s#@lzo2@#bcond_without#g" $@-t
else
	sed -i -e "s#@lzo2@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_LZMA
	sed -i -e "s#@lzma@#bcond_without#g" $@-t
else
	sed -i -e "s#@lzma@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_BZIP2
	sed -i -e "s#@bzip2@#bcond_without#g" $@-t
else
	sed -i -e "s#@bzip2@#bcond_with#g" $@-t
endif
if BUILD_COMPRESS_ZSTD
	sed -i -e "s#@zstd@#bcond_without#g" $@-t
else
	sed -i -e "s#@zstd@#bcond_with#g" $@-t
endif
if BUILD_LIBNOZZLE
	sed -i -e "s#@libnozzle@#bcond_without#g" $@-t
else
	sed -i -e "s#@libnozzle@#bcond_with#g" $@-t
endif
if BUILD_RUNAUTOGEN
	sed -i -e "s#@runautogen@#bcond_without#g" $@-t
else
	sed -i -e "s#@runautogen@#bcond_with#g" $@-t
endif
if OVERRIDE_RPM_DEBUGINFO
	sed -i -e "s#@overriderpmdebuginfo@#bcond_without#g" $@-t
else
	sed -i -e "s#@overriderpmdebuginfo@#bcond_with#g" $@-t
endif
if BUILD_RPM_DEBUGINFO
	sed -i -e "s#@rpmdebuginfo@#bcond_without#g" $@-t
else
	sed -i -e "s#@rpmdebuginfo@#bcond_with#g" $@-t
endif
if BUILD_MAN
	sed -i -e "s#@buildman@#bcond_without#g" $@-t
else
	sed -i -e "s#@buildman@#bcond_with#g" $@-t
endif
if INSTALL_TESTS
	sed -i -e "s#@installtests@#bcond_without#g" $@-t
else
	sed -i -e "s#@installtests@#bcond_with#g" $@-t
endif
	sed -i -e "s#@defaultadmgroup@#$(DEFAULTADMGROUP)#g" $@-t
	chmod a-w $@-t
	mv $@-t $@
	rm -f $@-t*

$(TARGZFILE):
	$(MAKE) dist

RPMBUILDOPTS	= --define "_sourcedir $(abs_builddir)" \
		  --define "_specdir $(abs_builddir)" \
		  --define "_builddir $(abs_builddir)" \
		  --define "_srcrpmdir $(abs_builddir)" \
		  --define "_rpmdir $(abs_builddir)"

srpm: clean
	$(MAKE) $(SPEC) $(TARGZFILE)
	rpmbuild $(RPMBUILDOPTS) --nodeps -bs $(SPEC)

rpm: clean
	$(MAKE) $(SPEC) $(TARGZFILE)
	rpmbuild $(RPMBUILDOPTS) -ba $(SPEC)

# release/versioning
BUILT_SOURCES	= .version
.version:
	echo $(VERSION) > $@-t && mv $@-t $@

dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version
	echo $(SOURCE_EPOCH) > $(distdir)/source_epoch

gen_start_date = 2000-01-01
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d $(abs_srcdir)/.git; then				\
		LC_ALL=C $(top_srcdir)/build-aux/gitlog-to-changelog	\
			--since=$(gen_start_date) > $(distdir)/cl-t;	\
		rm -f $(distdir)/ChangeLog;				\
		mv $(distdir)/cl-t $(distdir)/ChangeLog;		\
	fi
