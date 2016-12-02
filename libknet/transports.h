#include <netinet/in.h>
#include <netinet/sctp.h>

knet_transport_ops_t *get_udp_transport(void);

const char *_transport_print_ip(const struct sockaddr_storage *ss);
int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type);

