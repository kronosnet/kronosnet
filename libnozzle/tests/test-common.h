/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __NOZZLE_TEST_COMMON_H__
#define __NOZZLE_TEST_COMMON_H__

#include "internals.h"
#include "libnozzle.h"

/*
 * error codes from automake test-driver
 */

#define PASS	0
#define SKIP	77
#define ERROR	99
#define FAIL	-1

/*
 * common facilities
 */

void need_root(void);
int is_if_in_system(char *name);

#endif
