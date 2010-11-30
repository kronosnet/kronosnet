#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <signal.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

static int knet_sock[2];
static knet_handle_t knet_h;

static in_port_t tok_inport(char *str)
{
	int value = atoi(str);

	if ((value < 0) || (value > UINT16_MAX))
		return 0;

	return (in_port_t) value;
}

static int tok_inaddrport(char *str, struct sockaddr_in *addr)
{
	char *strhost, *strport, *tmp = NULL;

	strhost = strtok_r(str, ":", &tmp);
	strport = strtok_r(NULL, ":", &tmp);

	if (strport == NULL)
		addr->sin_port = htons(KNET_RING_DEFPORT);
	else
		addr->sin_port = htons(tok_inport(strport));

	return inet_aton(strhost, &addr->sin_addr);
}

static void print_usage(char *name)
{
	printf("usage: %s <localip>[:<port>] <remoteip>[:port] [...]\n", name);
	printf("example: %s 0.0.0.0 192.168.0.2\n", name);
}

static void argv_to_hosts(int argc, char *argv[])
{
	int err, i;
	struct sockaddr_in *address;
	struct knet_host *host;
	struct knet_listener *listener;

	listener = malloc(sizeof(struct knet_listener));

	if (listener == NULL) {
		log_error("Unable to create listener");
		exit(EXIT_FAILURE);
	}

	memset(listener, 0, sizeof(struct knet_listener));

	address = (struct sockaddr_in *) &listener->address;

	address->sin_family = AF_INET;
	err = tok_inaddrport(argv[1], address);

	if (err < 0) {
		log_error("Unable to convert ip address: %s", argv[1]);
		exit(EXIT_FAILURE);
	}

	err = knet_listener_add(knet_h, listener);

	if (err != 0) {
		log_error("Unable to start knet listener");
		exit(EXIT_FAILURE);
	}

	for (i = 2; i < argc; i++) {
		host = malloc(sizeof(struct knet_host));

		if (host == NULL) {
			log_error("Unable to allocate new knet_host");
			exit(EXIT_FAILURE);
		}

		memset(host, 0, sizeof(struct knet_host));

		host->node_id = i - 1;
		host->link = malloc(sizeof(struct knet_link));

		if (host->link == NULL) {
			log_error("Unable to allocate new knet_link");
			exit(EXIT_FAILURE);
		}

		memset(host->link, 0, sizeof(struct knet_link));

		knet_link_timeout(host->link, 1000, 5000, 2048);

		host->link->sock = listener->sock;
		host->link->address.ss_family = AF_INET;

		err = tok_inaddrport(argv[i], (struct sockaddr_in *) &host->link->address);

		if (err < 0) {
			log_error("Unable to convert ip address: %s", argv[i]);
			exit(EXIT_FAILURE);
		}

		if (knet_host_add(knet_h, host) != 0) {
			log_error("Unable to add new knet_host");
			exit(EXIT_FAILURE);
		}
	}
}

/* Testing the latency/timeout:
 *   # tc qdisc add dev lo root handle 1:0 netem delay 1s limit 1000
 *   # tc -d qdisc show dev lo
 *   # tc qdisc del dev lo root
 */
static void check_links(void)
{
	struct knet_host *i;
	struct knet_link *j;

	knet_host_acquire(knet_h, &i, 0);

	while (i != NULL) {
		for (j = i->link; j != NULL; j = j->next) {
			printf("link %p latency is %llums, status: %s\n",
				j, j->latency,
				(j->enabled == 0) ? "disabled" : "enabled");
		}
		i = i->next;
	}

	knet_host_release(knet_h);
}

static void sigint_handler(int signum)
{
	int err;

	printf("Cleaning up...\n");

	if (knet_h != NULL) {
		err = knet_handle_free(knet_h);

		if (err != 0) {
			log_error("Unable to cleanup before exit");
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	char buff[1024];
	size_t len;
	fd_set rfds;
	struct timeval tv;

	if (argc < 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, IPPROTO_IP, knet_sock) != 0) {
		log_error("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	knet_h = NULL;

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		log_error("Unable to configure SIGINT handler");
		exit(EXIT_FAILURE);
	}

	if ((knet_h = knet_handle_new(knet_sock[0])) == NULL) {
		log_error("Unable to create new knet_handle_t");
		exit(EXIT_FAILURE);
	}

	argv_to_hosts(argc, argv);

	knet_handle_setfwd(knet_h, 1);

	while (1) {
		check_links();

		log_info("Sending 'Hello World!' frame");
		write(knet_sock[1], "Hello World!", 13);

		tv.tv_sec = 5;
		tv.tv_usec = 0;

 select_loop:
		FD_ZERO(&rfds);
		FD_SET(knet_sock[1], &rfds);

		len = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);

		if (len < 0) {
			log_error("Unable select over knet_handle_t");
			exit(EXIT_FAILURE);
		} else if (FD_ISSET(knet_sock[1], &rfds)) {
			len = read(knet_sock[1], buff, sizeof(buff));
			printf("Received data (%zu bytes): '%s'\n", len, buff);
		}

		if ((tv.tv_sec > 0) || (tv.tv_usec > 0))
			goto select_loop;
	}

	/* FIXME: allocated hosts should be free'd */

	return 0;
}
