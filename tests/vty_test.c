#include "config.h"

#include <unistd.h>

#include "utils.h"
#include "vty.h"

extern int vty_max_connections;

static int knet_vty_set_max_check(void)
{
	int max_conn = vty_max_connections;

	log_info("Testing knet_vty_set_max_connections");

	if (knet_vty_set_max_connections(8) < 0) {
		log_error("Unable to set max connections");
		return -1;
	}

	log_info("Testing ERROR conditions");

	log_info("Setting max_connections to 0");

	if (!knet_vty_set_max_connections(0)) {
		log_error("Check knet_vty_set_max_connections filters");
		return -1;
	}

	log_info("Setting max_connections to %d", KNET_VTY_TOTAL_MAX_CONN+1);

	if (!knet_vty_set_max_connections(KNET_VTY_TOTAL_MAX_CONN+1)) {
		log_error("Check knet_vty_set_max_connections filters");
		return -1;
	}


	knet_vty_set_max_connections(max_conn);

	return 0;
}

static int knet_vty_init_check(void)
{
	int sock;

	log_info("Testing knet_vty_init");

	log_info("Testing bind to all default port");

	sock = knet_vty_init_listener(NULL, "50000");
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to localhost v4 default port");

	sock = knet_vty_init_listener("127.0.0.1", "50000");
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to localhost v6 default port");

	sock = knet_vty_init_listener("::1", "50000");
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to all v6 default port");

	sock = knet_vty_init_listener("::", "50000");
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to all v4 default port");

	sock = knet_vty_init_listener("0.0.0.0", "50000");
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing ERROR conditions");

	log_info("Testing bind to wrong v4 default port");

	sock = knet_vty_init_listener("255.255.255.255.255", "50000");
	if (sock >= 0) {
		log_error("Something is wrong with knet_vty_init_listener v4 ip handling");
		return -1;
	}

	log_info("Testing bind to wrong v6 default port");

	sock = knet_vty_init_listener("fffff::1", "50000");
	if (sock >= 0) {
		log_error("Something is wrong with knet_vty_init_listener v4 ip handling");
		return -1;
	}

	return 0;
}

int main(void)
{
	if (knet_vty_init_check() < 0)
		return -1;

	if (knet_vty_set_max_check() < 0)
		return -1;

	return 0;
}
