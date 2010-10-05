MAINTAINERCLEANFILES	= Makefile.in

docbook			= Kronosnet

DOCBOOK_FORMATS := html

%.txt: $(wildcard %/en-US/*.xml)
	@echo Building $*
	cd $* && $(PUBLICAN) build --publish --langs=all --formats=$(DOCBOOK_FORMATS)
	touch $@

docbook_txt = $(docbook:%=%.txt)

all-local: $(docbook_txt) */publican.cfg

clean-local:
	@rm -rf $(docbook_txt)
	@for book in $(docbook); do rm -rf $$book/tmp $$book/publish; done
