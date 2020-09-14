/*
 * Copyright (C) 2015-2020 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include <stdio.h>

#include "onwire.h"

int main(void)
{
	printf("\nKronosnet network header size printout:\n\n");
	printf("KNET_HEADER_ALL_SIZE: %zu\n", KNET_HEADER_ALL_SIZE);
	printf("KNET_HEADER_SIZE: %zu\n", KNET_HEADER_SIZE);
	printf("KNET_HEADER_PING_V1_SIZE: %zu (%zu)\n", KNET_HEADER_PING_V1_SIZE, sizeof(struct knet_header_payload_ping_v1));
	printf("KNET_HEADER_PMTUD_SIZE: %zu (%zu)\n", KNET_HEADER_PMTUD_SIZE, sizeof(struct knet_header_payload_pmtud));
	printf("KNET_HEADER_DATA_SIZE: %zu (%zu)\n", KNET_HEADER_DATA_SIZE, sizeof(struct knet_header_payload_data));

	return 0;
}
