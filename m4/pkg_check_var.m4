# Copyright (C) 2020-2024 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+

# PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
# [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------
# Retrieves the value of the pkg-config variable for the given module.

m4_ifndef([PKG_CHECK_VAR],
	  [AC_DEFUN([PKG_CHECK_VAR],
		    [AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
		     AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl
		     _PKG_CONFIG([$1], [variable="][$3]["], [$2])
		     AS_VAR_COPY([$1], [pkg_cv_][$1])
		     AS_VAR_IF([$1], [""], [$5], [$4])dnl
		    ])# PKG_CHECK_VAR
])
