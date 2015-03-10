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
	printf("knet_hostinfo: %zu\n", sizeof(struct knet_hostinfo));

	return 0;
}
