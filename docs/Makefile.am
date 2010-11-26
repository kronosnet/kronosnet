MAINTAINERCLEANFILES	= Makefile.in

EXTRA_DIST		= kronosnet_architecture.odp

docbook			= Kronosnet

DOCBOOK_FORMATS := pdf,html,html-single,txt

%.txt: $(wildcard %/en-US/*.xml)
	@echo Building $*
	cd $* && $(PUBLICAN) build --publish --langs=all --formats=$(DOCBOOK_FORMATS)
	touch $@

docbook_txt = $(docbook:%=%.txt)

all-local: $(docbook_txt) */publican.cfg

clean-local:
	@rm -rf $(docbook_txt)
	@for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done

push:
	@for book in $(docbook); do \
		rsync -rtz --progress $$book/publish/* fabbione@kronosnet.org:kronosnet/docs; \
		rsync -rtz --progress kronosnet_architecture.odp fabbione@kronosnet.org:kronosnet/docs/kronosnet_architecture.odp; \
	done
