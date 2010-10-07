#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "ring.h"
#include "utils.h"


int knet_ring_listen(in_port_t port)
{
	int err, sock, value;
	struct sockaddr_in6 addr;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);

	if (sock < 0) {
		log_error("unable to open netsocket error");
		return sock;
	}

	value = KNET_RING_RCVBUFF;
	err = setsockopt(sock,
			SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0) {
		log_error("unable to set receive buffer");
	}

	value = fcntl(sock, F_GETFD, 0);

	if (value < 0) {
		log_error("unable to get close-on-exec flag");
		goto clean_fail;
	}

	value |= FD_CLOEXEC;
	err = fcntl(sock, F_SETFD, value);

	if (err < 0) {
		log_error("unable to set close-on-exec flag");
		goto clean_fail;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin6_family = AF_INET6;
	addr.sin6_port = ntohs(port);
	memcpy(&addr.sin6_addr, &in6addr_any, sizeof(struct in6_addr));

	err = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

	if (err < 0) {
		log_error("unable to bind to netsocket");
		goto clean_fail;
	}

	return sock;

clean_fail:
	close(sock);
	return -1;
}

int knet_ring_connect(struct knet_ring *ring)
{
	ring->sock = socket(ring->info.sa_family, SOCK_DGRAM, 0);

	if (ring->sock < 0) {
		log_error("unable create ring socket");
		return ring->sock;
	}

	if (connect(ring->sock, (struct sockaddr *) &ring->info,
						sizeof(ring->info)) != 0) {
		log_error("unable to connect ring socket");
		goto clean_fail;
	}

	return ring->sock;

clean_fail:
	close(ring->sock);
	ring->sock = -1;

	return ring->sock;
}

void knet_ring_disconnect(struct knet_ring *ring)
{
	if (ring->sock > 0) {
		close(ring->sock);
	}
}

