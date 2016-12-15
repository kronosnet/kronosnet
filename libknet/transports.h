#include <netinet/in.h>
#include <netinet/sctp.h>

knet_transport_ops_t *get_udp_transport(void);
knet_transport_ops_t *get_sctp_transport(void);

int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type);
void _close_socket(knet_handle_t knet_h, int sockfd);
void _handle_socket_notification(knet_handle_t knet_h, int sockfd, struct iovec *iov, size_t iovlen);

int _transport_addrtostr(const struct sockaddr *sa, socklen_t salen, char *str[2]);
void _transport_addrtostr_free(char *str[2]);

