#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "libknet.h"
#include "libknet-private.h"
#include "netutils.h"

#define KNET_PORT 50000
#define KNET_BENCH_LOOPNUM 100000000

int main(int argc, char *argv[])
{
	struct knet_link *head;
	struct sockaddr_in address;
	struct timespec bench_start, bench_end;
	unsigned long long i, bench_diff;

	head = malloc(sizeof(struct knet_link));

	if (head == NULL) {
		printf("Unable to create knet_link\n");
		exit(EXIT_FAILURE);
	}

	memset(head, 0, sizeof(struct knet_link));

	address.sin_family = AF_INET;
	address.sin_port = htons(KNET_PORT);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	memmove(&head->dst_addr, &address, sizeof(address));

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bench_start);

	for (i = 0; i < KNET_BENCH_LOOPNUM; i++) {
		cmpaddr((struct sockaddr_storage *) &address, sizeof(address),
			(struct sockaddr_storage *) &head->dst_addr,
							sizeof(head->dst_addr));
	}

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &bench_end);

	printf("start sec: %3lu, nsec: %9lu\n  end sec: %3lu, nsec: %9lu\n",
				bench_start.tv_sec, bench_start.tv_nsec,
				bench_end.tv_sec, bench_end.tv_nsec);

	timespec_diff(bench_start, bench_end, &bench_diff);

	printf("end - start = %llums\n", bench_diff);

	return 0;
}
