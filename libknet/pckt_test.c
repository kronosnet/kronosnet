#include <stdio.h>

#include "onwire.h"

int main(void)
{
	printf("\nKronosnet network header size printout:\n\n");
	printf("KNET_PING_SIZE (needs renaming): %zu\n", KNET_PING_SIZE);
	printf("KNET_FRAME_SIZE: %zu\n", KNET_FRAME_SIZE);
	printf("KNET_FRAME_PING_SIZE: %zu (%zu)\n", KNET_FRAME_PING_SIZE, sizeof(struct knet_header_payload_ping));
	printf("KNET_FRAME_PMTUD_SIZE: %zu (%zu)\n", KNET_FRAME_PMTUD_SIZE, sizeof(struct knet_header_payload_pmtud));
	printf("KNET_FRAME_DATA_SIZE: %zu (%zu)\n", KNET_FRAME_DATA_SIZE, sizeof(struct knet_header_payload_data));
	printf("\n");
	printf("knet_hinfo_data: %zu\n", sizeof(struct knet_hinfo_data));

	return 0;
}
