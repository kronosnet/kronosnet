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

#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#include "common.h"

int main(int argc, char **argv)
{
	int err = 0;
	int rv;
	int check_crc = 0;
	char defaddr[8] = "0.0.0.0";
	char defport[8] = "50000";
	char *address = NULL, *port = NULL;

	struct sockaddr_storage ss, newss;
	int sock, newsock;
	socklen_t sock_len = sizeof(ss);

	int rx_epoll;
	struct epoll_event ev;
	struct epoll_event events[32];
	int i, nev;

	struct mmsghdr msg[256];

	while ((rv = getopt(argc, argv, "a:p:c")) != EOF) {
		switch(rv) {
			case 'a':
				address = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'c':
				check_crc = 1;
				break;
			default:
				fprintf(stderr, "Unknown option\n");
				return -1;
				break;
		}
	}

	memset(&msg, 0, sizeof(msg));
	if (setup_rx_buffers(msg) < 0) {
		return -1;
	}

	rx_epoll = epoll_create(32);
	if (rx_epoll < 0) {
		fprintf(stderr, "Unable to create rx_epoll (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	/*
	 * setup SCTP server socket
	 */

	if (!address) {
		address = defaddr;
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

	if (setup_sctp_server_sock_opts(sock, &ss) < 0) {
		fprintf(stderr, "Unable to set socket options\n");
		goto out;
	}

	if (bind(sock, (struct sockaddr *)&ss, sizeof(struct sockaddr_storage)) < 0) {
		fprintf(stderr, "Unable to bind socket (%d): %s\n",
			errno, strerror(errno));
		goto out;
	}

	if (listen(sock, 5) < 0) {
		fprintf(stderr, "Unable to listen socket (%d): %s\n",
			errno, strerror(errno));
		goto out;
	}

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
		nev = epoll_wait(rx_epoll, events, 32, -1);
		if (nev < 0) {
			fprintf(stderr, "SCTP listen handler EPOLL ERROR (%d): %s\n",
				errno, strerror(errno));
		}

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == sock) {
				newsock = accept(sock, (struct sockaddr *)&newss, &sock_len);
				if (newsock < 0) {
					fprintf(stderr, "Error accepting connection (%d): %s\n",
					errno, strerror(errno));
					continue;
				}
				if (setup_sctp_common_sock_opts(newsock, &newss) < 0) {
					fprintf(stderr, "Error setting sockopts\n");
					close(newsock);
					continue;
				}
				memset(&ev, 0, sizeof(struct epoll_event));
				ev.events = EPOLLIN;
				ev.data.fd = newsock;
				if (epoll_ctl(rx_epoll, EPOLL_CTL_ADD, newsock, &ev) < 0) {
					fprintf(stderr, "Unable to add accept new connection (%d): %s\n",
						errno, strerror(errno));
					close(newsock);
				}
				fprintf(stderr, "Accepted socket: %d\n", newsock);
			} else {
				get_incoming_data(events[i].data.fd, msg, check_crc);
			}
		}
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
