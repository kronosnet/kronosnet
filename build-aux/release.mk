# to build official release tarballs, handle tagging and publish.

gpgsignkey =  # signing key

project = kronosnet

deliverables = $(project)-$(version).sha256 \
               $(project)-$(version).tar.bz2 \
               $(project)-$(version).tar.gz \
               $(project)-$(version).tar.xz

all: checks setup tag tarballs sha256 sign

checks:
ifeq (,$(version))
	@echo ERROR: need to define version=
	@exit 1
endif
	@if [ ! -d .git ]; then \
		echo This script needs to be executed from top level cluster git tree; \
		exit 1; \
	fi

setup: checks
	./autogen.sh
	./configure
	make maintainer-clean

tag: setup ./tag-$(version)

tag-$(version):
ifeq (,$(release))
	@echo Building test release $(version), no tagging
	echo '$(version)' > .tarball-version
else
	# following will be captured by git-version-gen automatically
	git tag -a -m "v$(version) release" v$(version) HEAD
	@touch $@
endif

tarballs: tag
	./autogen.sh
	./configure
	#make distcheck (disabled.. needs root)
	make dist

sha256: $(project)-$(version).sha256

# NOTE: dependency backtrack may fail trying to sign missing tarballs otherwise
#       (actually, only when signing tarballs directly, but doesn't hurt anyway)
$(deliverables): tarballs

$(project)-$(version).sha256:
	# checksum anything from deliverables except for in-prep checksums file
	sha256sum $(deliverables:$@=) | sort -k2 > $@

ifeq (,$(gpgsignkey))
sign: $(deliverables)
	@echo No GPG signing key defined
else
sign: $(project)-$(version).sha256.asc  # "$(deliverables:=.asc)" to sign all
endif

# NOTE: cannot sign multiple files at once
$(project)-$(version).%.asc: $(project)-$(version).%
	gpg --default-key "$(gpgsignkey)" \
		--detach-sign \
		--armor \
		$<

publish:
ifeq (,$(release))
	@echo Building test release $(version), no publishing!
else
	@echo CHANGEME git push --tags origin
	@echo CHANGEME scp $(project)-$(version).* \
		fedorahosted.org:$(project)
endif

clean:
	rm -rf $(project)-* tag-* .tarball-version
