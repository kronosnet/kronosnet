#include "config.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <zlib.h>

#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#include "common.h"

int main(int argc, char **argv)
{
	int err = 0;
	int rv;
	int enable_crc = 0;
	char defport[8] = "50000";
	char *address = NULL, *port = NULL;

	struct sockaddr_storage ss;
	int sock;

	int rx_epoll;
	struct epoll_event ev;
	struct epoll_event events[32];
	int i, nev;

	struct mmsghdr msg_in[256];

	struct mmsghdr msg_out[256];
	struct iovec iov_out[256];

	int sent_msgs;

	while ((rv = getopt(argc, argv, "a:p:c")) != EOF) {
		switch(rv) {
			case 'a':
				address = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'c':
				enable_crc = 1;
				break;
			default:
				fprintf(stderr, "Unknown option\n");
				return -1;
				break;
		}
	}

	/*
	 * Setup RX buffers
	 */
	memset(&msg_in, 0, sizeof(struct mmsghdr));
	if (setup_rx_buffers(msg_in) < 0) {
		return -1;
	}

	/*
	 * setup TX buffers
	 */
	for (i = 0; i < 256; i++) {
		iov_out[i].iov_base = (void *)malloc(65536);
		if (!iov_out[i].iov_base) {
			fprintf(stderr, "Unable to malloc RX buffers(%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
		if (enable_crc) {
			unsigned int *dataint = (unsigned int *)iov_out[i].iov_base;
			unsigned int crc;
			int j;

			for (j=1; j<65536/sizeof(int); j++) {
				dataint[j] = rand();
			}
			crc = crc32(0, NULL, 0);
			dataint[0] = crc32(crc, (Bytef*)&dataint[1], 65536-sizeof(int));
		} else {
			memset(iov_out[i].iov_base, 0, 65536);
		}
		iov_out[i].iov_len = 65536;
	}

	rx_epoll = epoll_create(32);
	if (rx_epoll < 0) {
		fprintf(stderr, "Unable to create rx_epoll (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	/*
	 * setup SCTP client socket
	 */

	if (!address) {
		fprintf(stderr, "No server address specified (use -a <ipaddress>).\n");
		fprintf(stderr, "Scanning the internet for SCTP servers (this might take a while).\n");
		while (1) {
			fprintf(stderr, "...");
			sleep(1);
		}
	}

	if (!port) {
		port = defport;
	}

	if (strtoaddr(address, port, &ss, sizeof(struct sockaddr_storage)) < 0) {
		return -1;
	}

	sock = socket(ss.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (sock < 0) {
		fprintf(stderr, "unable to create socket (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (setup_sctp_common_sock_opts(sock, &ss) < 0) {
		fprintf(stderr, "Unable to set socket options\n");
		goto out;
	}

	if (connect(sock, (struct sockaddr *)&ss, sizeof(struct sockaddr_storage)) < 0) {
		if ((errno != EALREADY) && (errno != EINPROGRESS) && (errno != EISCONN)) {
			fprintf(stderr, "Unable to connect to server: (%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
	}

	/*
	 * i am supposed to check SO_ERROR to see if it's connected, but this is a PoC
	 * and I am lazy
	 */

	sleep(1);

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(rx_epoll, EPOLL_CTL_ADD, sock, &ev) < 0) {
		fprintf(stderr, "Unable to add listen socket to epoll (%d): %s\n",
			errno, strerror(errno));
		goto out;
	}

	/*
	 * main loop
	 */

	while(1) {
		nev = epoll_wait(rx_epoll, events, 32, 0);
		if (nev < 0) {
			fprintf(stderr, "SCTP listen handler EPOLL ERROR (%d): %s\n",
				errno, strerror(errno));
		} else {
			for (i = 0; i < nev; i++) {
				if (events[i].data.fd == sock) {
					get_incoming_data(events[i].data.fd, msg_in, enable_crc);
				}
			}
		}

		sleep(1);

		memset(&msg_out, 0, sizeof(msg_out));
		for (i = 0; i < 256; i++) {
			memset(&msg_out[i].msg_hdr, 0, sizeof(struct msghdr));
			msg_out[i].msg_hdr.msg_name = &ss;
			msg_out[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			msg_out[i].msg_hdr.msg_iov = &iov_out[i];
			msg_out[i].msg_hdr.msg_iovlen = 1;
		}

		sent_msgs = sendmmsg(sock, msg_out, 256, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (sent_msgs <= 0) {
			fprintf(stderr, "Error sending msgs (%d): %s\n",
				errno, strerror(errno));
		}
		if (sent_msgs != 256) {
			fprintf(stderr, "Unable to send all 256 messages at once (sent: %d)\n",
				sent_msgs);
		}
		fprintf(stderr, "sent %d messages\n", sent_msgs);
	}

out:
	if (sock >= 0) {
		close(sock);
	}
	if (rx_epoll >= 0) {
		close(rx_epoll);
	}

	return err;
}
#else
int main(void)
{
	printf("SCTP unsupported in this build\n");
	errno = EINVAL;
	return -1;
}
#endif
