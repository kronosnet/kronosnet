/*
 * Copyright (C) 2015-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include <stdio.h>

#include "onwire.h"

int main(void)
{
	printf("\nKronosnet network header size printout:\n\n");
	printf("KNET_HEADER_ALL_SIZE: %zu\n", KNET_HEADER_ALL_SIZE);
	printf("KNET_HEADER_SIZE: %zu\n", KNET_HEADER_SIZE);
	printf("KNET_HEADER_PING_SIZE: %zu (%zu)\n", KNET_HEADER_PING_SIZE, sizeof(struct knet_header_payload_ping));
	printf("KNET_HEADER_PMTUD_SIZE: %zu (%zu)\n", KNET_HEADER_PMTUD_SIZE, sizeof(struct knet_header_payload_pmtud));
	printf("KNET_HEADER_DATA_SIZE: %zu (%zu)\n", KNET_HEADER_DATA_SIZE, sizeof(struct knet_header_payload_data));
	printf("\n");
	printf("KNET_HOSTINFO_ALL_SIZE: %zu\n", KNET_HOSTINFO_ALL_SIZE);
	printf("KNET_HOSTINFO_SIZE: %zu\n", KNET_HOSTINFO_SIZE);
	printf("KNET_HOSTINFO_LINK_STATUS_SIZE: %zu (%zu)\n", KNET_HOSTINFO_LINK_STATUS_SIZE, sizeof(struct knet_hostinfo_payload_link_status));

	return 0;
}
