#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

static in_port_t tok_inport(char *str)
{
	int value = atoi(str);

	if ((value < 0) || (value > UINT16_MAX))
		return 0;

	return (in_port_t) value;
}

static int tok_inaddrport(char *str, struct sockaddr_in *addr)
{
	char *strhost, *strport, *tmp;

	strhost = strtok_r(str, ":", &tmp);
	strport = strtok_r(NULL, ":", &tmp);

	if (strport == NULL)
		addr->sin_port = htons(KNET_RING_DEFPORT);
	else
		addr->sin_port = htons(tok_inport(strport));

	return inet_aton(strhost, &addr->sin_addr);
}

static int server_start(in_port_t port)
{
	int sockfd;
	struct sockaddr_in srv_sa;

	srv_sa.sin_family = AF_INET;
	srv_sa.sin_port = htons(port);
	srv_sa.sin_addr.s_addr = htonl(INADDR_ANY);

	log_info("Opening ring socket on port %u", port);
	sockfd =
	    knet_ring_listen((struct sockaddr *) &srv_sa, sizeof(srv_sa));

	if (sockfd < 0) {
		log_error("Unable to open ring socket");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

static void wait_data_loop(int sockfd, time_t timeout)
{
	int err;
	fd_set rfds;
	struct timeval tv;
	struct knet_frame recv_frame;

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	while ((tv.tv_sec > 0) || (tv.tv_usec > 0)) {
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		err = select(sockfd + 1, &rfds, NULL, NULL, &tv);

		if (err == -1) {
			log_error("Unable to wait for ping messages");
			exit(EXIT_FAILURE);
		} else if (!FD_ISSET(sockfd, &rfds)) {
			continue;
		}

		err =
		    recv(sockfd, &recv_frame, sizeof(recv_frame),
			 MSG_DONTWAIT);

		if (err != sizeof(recv_frame)) {
			if (errno == 0)
				errno = EBADMSG;
			log_error("Received ping was too short");
		} else {
			log_info("Ping successfully received!");
		}
	}
}

static void print_usage(char *name)
{
	printf("usage: %s <port> <remoteip>[:port]\n", name);
}

int main(int argc, char *argv[])
{
	int srv_sockfd, err;
	struct knet_ring ring;
	struct sockaddr_in *ring_in;
	struct knet_frame send_frame;

	if (argc != 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	srv_sockfd = server_start(tok_inport(argv[1]));

	ring_in = (struct sockaddr_in *) &ring.info;
	ring.info.ss_family = AF_INET;

	err = tok_inaddrport(argv[2], ring_in);

	if (err < 0) {
		log_error("Unable to convert ip address: %s", argv[2]);
		exit(EXIT_FAILURE);
	}

	send_frame.magic = KNET_FRAME_MAGIC;
	send_frame.version = KNET_FRAME_VERSION;
	send_frame.type = KNET_FRAME_PING;

	while (1) {
		log_info("Sending ping");

		err =
		    knet_ring_send(srv_sockfd, &ring, &send_frame,
				   sizeof(send_frame));

		if (err != sizeof(struct knet_frame)) {
			log_error("Unable to send ping");
			exit(EXIT_FAILURE);
		}

		wait_data_loop(srv_sockfd, 5);	/* wait data for 5 seconds */
	}

	log_info("Closing sockets");
	close(srv_sockfd);

	return 0;
}
