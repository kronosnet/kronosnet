#!/bin/sh
#
# Copyright (C) 2021-2026 Red Hat, Inc.  All rights reserved.
#
# Authors: Christine Caulfield <ccaulfie@redhat.com>
#          Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#
#
# Regerate the FFI bindings in src/sys from the current headers
#

bindgen="$1"
srcheader="$2"
dstrs="$3"
filter="$4"

"$bindgen" \
	--no-prepend-enum-name \
	--no-layout-tests \
	--no-doc-comments \
	--generate functions,types,vars \
	--fit-macro-constant-types \
	--allowlist-var="^(${filter}_.*)" \
	--allowlist-type=.* \
	--allowlist-function=.* \
	"$srcheader" -o "$dstrs"
