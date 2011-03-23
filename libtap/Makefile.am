MAINTAINERCLEANFILES	= Makefile.in

sources			= libtap.c

libversion		= 0:0:0

AM_CFLAGS		= -fPIC

# override global LIBS that pulls in lots of craft we don't need here
LIBS			= -lpthread

include_HEADERS		= libtap.h

noinst_HEADERS		= libtap-private.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= $(sources)

libtap_la_LDFLAGS	= -Wl,-version-script,libtap_exported_sym \
			  --export-dynamic \
			  -version-info $(libversion)

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check_PROGRAMS		= tap_test

tap_test_SOURCES	= $(sources)

tap_test_CPPFLAGS	= -DTEST \
			  -DABSBUILDDIR=\"$(abs_builddir)\"

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d

uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;

