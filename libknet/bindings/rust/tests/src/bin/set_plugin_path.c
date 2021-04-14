/*
 * Copyright (C) 2021 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+
 */

#include <stdio.h>

#include "test-common.h"
#include "internals.h"
#include "libknet.h"

// Set the path for compress/crypto plugins when running the test program
void set_plugin_path(knet_handle_t knet_h)
{
	struct knet_handle *handle = (struct knet_handle *)knet_h;
	char *plugins_path = find_plugins_path();
	if (plugins_path) {
		handle->plugin_path = plugins_path;
	}
}
