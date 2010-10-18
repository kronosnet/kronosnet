#include "config.h"

#include <unistd.h>

#include "utils.h"
#include "vty.h"

static int knet_vty_init_check(void)
{
	int sock;

	log_info("Testing knet_vty_init");

	log_info("Testing bind to all default port");

	sock = knet_vty_init_listener(NULL, KNET_VTY_DEFAULT_PORT);
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to localhost v4 default port");

	sock = knet_vty_init_listener("127.0.0.1", KNET_VTY_DEFAULT_PORT);
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to localhost v6 default port");

	sock = knet_vty_init_listener("::1", KNET_VTY_DEFAULT_PORT);
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to all v6 default port");

	sock = knet_vty_init_listener("::", KNET_VTY_DEFAULT_PORT);
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing bind to all v4 default port");

	sock = knet_vty_init_listener("0.0.0.0", KNET_VTY_DEFAULT_PORT);
	if (sock < 0) {
		log_error("Unable to init vty");
		return -1;
	}
	knet_vty_close_listener(sock);

	log_info("Testing ERROR conditions");

	log_info("Testing bind to wrong v4 default port");

	sock = knet_vty_init_listener("255.255.255.255.255", KNET_VTY_DEFAULT_PORT);
	if (sock >= 0) {
		log_error("Something is wrong with knet_vty_init_listener v4 ip handling");
		return -1;
	}

	log_info("Testing bind to wrong v6 default port");

	sock = knet_vty_init_listener("fffff::1", KNET_VTY_DEFAULT_PORT);
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

	return 0;
}
