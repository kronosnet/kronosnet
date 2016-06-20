/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LIBKNET_H__
#define __LIBKNET_H__

#include <stdint.h>
#include <netinet/in.h>

/*
 * libknet limits
 */

/*
 * Maximum number of hosts
 */

#define KNET_MAX_HOST 65536

/*
 * Maximum number of links between 2 hosts
 */

#define KNET_MAX_LINK 8

/*
 * Maximum packet size that should be written to datafd
 *  see knet_handle_new for details
 */

#define KNET_MAX_PACKET_SIZE 65536

/*
 * Buffers used for pretty logging
 *  host is used to store both ip addresses and hostnames
 */

#define KNET_MAX_HOST_LEN 64
#define KNET_MAX_PORT_LEN 6

/*
 * Some notifications can be generated either on TX or RX
 */

#define KNET_NOTIFY_TX 0
#define KNET_NOTIFY_RX 1

typedef struct knet_handle *knet_handle_t;

/*
 * Handle structs/API calls
 */

/*
 * knet_handle_new
 *
 * host_id  - Each host in a knet is identified with a unique
 *            ID. when creating a new handle local host_id
 *            must be specified (0 to UINT16T_MAX are all valid).
 *            It is the user's responsibility to check that the value
 *            is unique, or bad things might happen.
 *
 * log_fd   - Write file descriptor. If set to a value > 0, it will be used
 *            to write log packets (see below) from libknet to the application.
 *            Setting to 0 will disable logging from libknet.
 *            It is possible to enable logging at any given time (see logging API
 *            below).
 *            Make sure to either read from this filedescriptor properly and/or
 *            mark it O_NONBLOCK, otherwise if the fd becomes full, libknet could
 *            block.
 *
 * default_log_level -
 *            If logfd is specified, it will initialize all subsystems to log
 *            at default_log_level value. (see logging API below)
 *
 * on success, a new knet_handle_t is returned.
 * on failure, NULL is returned and errno is set.
 */

knet_handle_t knet_handle_new(uint16_t host_id,
			      int      log_fd,
			      uint8_t  default_log_level);

/*
 * knet_handle_free
 *
 * knet_h   - pointer to knet_handle_t
 *
 * Destroy a knet handle, free all resources
 *
 * knet_handle_free returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_free(knet_handle_t knet_h);

/*
 * knet_handle_enable_sock_notify
 *
 * knet_h   - pointer to knet_handle_t
 *
 * sock_notify_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * sock_notify_fn
 *            A callback function that is invoked every time
 *            a socket in the datafd pool will report an error (-1)
 *            or an end of read (0) (see socket.7).
 *            This function MUST NEVER block or add substantial delays.
 *            The callback is invoked in an internal unlocked area
 *            to allow calls to knet_handle_add_datafd/knet_handle_remove_datafd
 *            to swap/replace the bad fd.
 *            if both err and errno are 0, it means that the socket
 *            has received a 0 byte packet (EOF?).
 *            The callback function must either remove the fd from knet
 *            (by calling knet_handle_remove_fd()) or dup a new fd in its place.
 *            Failure to do this can cause problems.
 *
 * knet_handle_enable_sock_notify returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_enable_sock_notify(knet_handle_t knet_h,
				   void *sock_notify_fn_private_data,
				   void (*sock_notify_fn) (
						void *private_data,
						int datafd,
						int8_t channel,
						uint8_t tx_rx,
						int error,
						int errorno)); /* sorry! can't call it errno ;) */

/*
 * knet_handle_add_datafd
 *
 * IMPORTANT: In order to add datafd to knet, knet_handle_enable_sock_notify
 *            _MUST_ be set and be able to handle both errors (-1) and
 *            0 bytes read / write from the provided datafd.
 *            On read error (< 0) from datafd, the socket is automatically
 *            removed from polling to avoid spinning on dead sockets.
 *            It is safe to call knet_handle_remove_datafd even on sockets
 *            that have been removed.
 *
 * knet_h   - pointer to knet_handle_t
 *
 * *datafd  - read/write file descriptor.
 *            knet will read data here to send to the other hosts
 *            and will write data received from the network.
 *            Each data packet can be of max size KNET_MAX_PACKET_SIZE!
 *            Applications using knet_send/knet_recv will receive a
 *            proper error if the packet size is not within boundaries.
 *            Applications using their own functions to write to the
 *            datafd should NOT write more than KNET_MAX_PACKET_SIZE.
 *
 *            Please refer to handle.c on how to set up a socketpair.
 *
 *            datafd can be 0, and knet_handle_add_datafd will create a properly
 *            populated socket pair the same way as ping_test, or a value
 *            higher than 0. A negative number will return an error.
 *            On exit knet_handle_free will take care to cleanup the
 *            socketpair only if they have been created by knet_handle_add_datafd.
 *
 *            It is possible to pass either sockets or normal fds.
 *            User provided datafd will be marked as non-blocking and close-on-exit.
 *
 * *channel - This value has the same effect of VLAN tagging.
 *            A negative value will auto-allocate a channel.
 *            Setting a value between 0 and 31 will try to allocate that
 *            specific channel (unless already in use).
 *
 *            It is possible to add up to 32 datafds but be aware that each
 *            one of them must have a receiving end on the other host.
 *
 *            Example:
 *            hostA channel 0 will be delivered to datafd on hostB channel 0
 *            hostA channel 1 to hostB channel 1.
 *
 *            Each channel must have a unique file descriptor.
 *
 *            If your application could have 2 channels on one host and one
 *            channel on another host, then you can use dst_host_filter
 *            to manipulate channel values on TX and RX.
 *
 * knet_handle_add_datafd returns:
 *
 * 0 on success
 *   *datafd  will be populated with a socket if the original value was 0
 *            or if a specific fd was set, the value is untouched.
 *   *channel will be populated with a channel number if the original value
 *            was negative or the value is untouched if a specific channel
 *            was requested.
 *
 * -1 on error and errno is set.
 *   *datafd and *channel are untouched or empty.
 */

#define KNET_DATAFD_MAX 32

int knet_handle_add_datafd(knet_handle_t knet_h, int *datafd, int8_t *channel);

/*
 * knet_handle_remove_datafd
 *
 * knet_h   - pointer to knet_handle_t
 *
 * datafd   - file descriptor to remove.
 *            NOTE that if the socket/fd was created by knet_handle_add_datafd,
 *                 the socket will be closed by libknet.
 *
 * knet_handle_remove_datafd returns:
 *
 * 0 on success
 *
 * -1 on error and errno is set.
 */

int knet_handle_remove_datafd(knet_handle_t knet_h, int datafd);

/*
 * knet_handle_enable_sock_notify
 *
 * knet_h   - pointer to knet_handle_t
 *
 * sock_notify_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * sock_notify_fn
 *            A callback function that is invoked every time
 *            a socket in the datafd pool will report an error (-1)
 *            or an end of read (0) (see socket.7).
 *            This function MUST NEVER block or add substantial delays.
 *            The callback is invoked in an internal unlocked area
 *            to allow calls to knet_handle_add_datafd/knet_handle_remove_datafd
 *            to swap/replace the bad fd.
 *            if both err and errno are 0, it means that the socket
 *            has received a 0 byte packet (EOF?).
 *            The callback function must either remove the fd from knet
 *            (by calling knet_handle_remove_fd()) or dup a new fd in its place.
 *            Failure to do this can cause problems.
 *
 * knet_handle_enable_sock_notify returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_get_channel(knet_handle_t knet_h, const int datafd, int8_t *channel);

/*
 * knet_handle_get_datafd
 *
 * knet_h   - pointer to knet_handle_t
 *
 * channel  - get the datafd associated to this channel
 *
 * *datafd  - will contain the result
 *
 * knet_handle_get_datafd returns:
 *
 * 0 on success
 *   and *datafd will contain the results
 *
 * -1 on error and errno is set.
 *   and *datafd content is meaningless
 */

int knet_handle_get_datafd(knet_handle_t knet_h, const int8_t channel, int *datafd);

/*
 * knet_recv
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to buffer to store the received data
 *
 * buff_len - buffer lenght
 *
 * knet_recv is a commodity function to wrap iovec operations
 * around a socket. It returns a call to readv(2).
 */

ssize_t knet_recv(knet_handle_t knet_h,
		  char *buff,
		  const size_t buff_len,
		  const int8_t channel);

/*
 * knet_send
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to the buffer of data to send
 *
 * buff_len - length of data to send
 *
 * knet_send is a commodity function to wrap iovec operations
 * around a socket. It returns a call to writev(2).
 */

ssize_t knet_send(knet_handle_t knet_h,
		  const char *buff,
		  const size_t buff_len,
		  const int8_t channel);

/*
 * knet_send_sync
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to the buffer of data to send
 *
 * buff_len - length of data to send
 *
 * channel  - data channel to use (see knet_handle_add_datafd)
 *
 * All knet RX/TX operations are async for performance reasons.
 * There are applications that might need a sync version of data
 * transmission and receive errors in case of failure to deliver
 * to another host.
 * knet_send_sync bypasses the whole TX async layer and delivers
 * data directly to the link layer, and returns errors accordingly.
 * knet_send_sync allows to send only one packet to one host at
 * a time. It does NOT support multiple destinations or multicast
 * packets. Decision is still based on dst_host_filter_fn.
 *
 * knet_send_sync returns 0 on success and -1 on error.
 *
 * In addition to normal sendmmsg errors, knet_send_sync can fail
 * due to:
 *
 * ECANCELED - data forward is disabled
 * EFAULT    - dst_host_filter fatal error
 * EINVAL    - dst_host_filter did not provide
 *             dst_host_ids_entries on unicast pckts
 * E2BIG     - dst_host_filter did return more than one
 *             dst_host_ids_entries on unicast pckts
 * ENOMSG    - received unknown message type
 * EHOSTDOWN - unicast pckt cannot be delivered because
 *             dest host is not connected yet
 * ECHILD    - crypto failed
 * EAGAIN    - sendmmsg was unable to send all messages and
 *             there was no progress during retry
 */

int knet_send_sync(knet_handle_t knet_h,
		   const char *buff,
		   const size_t buff_len,
		   const int8_t channel);

/*
 * knet_handle_enable_filter
 *
 * knet_h   - pointer to knet_handle_t
 *
 * dst_host_filter_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * dst_host_filter_fn -
 *            is a callback function that is invoked every time
 *            a packet hits datafd (see knet_handle_new).
 *            the function allows users to tell libknet where the
 *            packet has to be delivered.
 *
 *            const unsigned char *outdata - is a pointer to the
 *                                           current packet
 *            ssize_t outdata_len          - lenght of the above data
 *            uint8_t tx_rx                - filter is called on tx or rx
 *                                           (see defines below)
 *            uint16_t this_host_id        - host_id processing the packet
 *            uint16_t src_host_id         - host_id that generated the
 *                                           packet
 *            uint16_t *dst_host_ids       - array of KNET_MAX_HOST uint16_t
 *                                           where to store the destinations
 *            size_t *dst_host_ids_entries - number of hosts to send the message
 *
 * dst_host_filter_fn should return
 * -1 on error, packet is discarded.
 *  0 packet is unicast and should be sent to dst_host_ids and there are
 *    dst_host_ids_entries in the buffer.
 *  1 packet is broadcast/multicast and is sent all hosts.
 *    contents of dst_host_ids and dst_host_ids_entries are ignored.
 *  (see also kronosnetd/etherfilter.* for an example that filters based
 *   on ether protocol)
 *
 * knet_handle_enable_filter returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_enable_filter(knet_handle_t knet_h,
			      void *dst_host_filter_fn_private_data,
			      int (*dst_host_filter_fn) (
					void *private_data,
					const unsigned char *outdata,
					ssize_t outdata_len,
					uint8_t tx_rx,
					uint16_t this_host_id,
					uint16_t src_host_id,
					int8_t *channel,
					uint16_t *dst_host_ids,
					size_t *dst_host_ids_entries));

/*
 * knet_handle_setfwd
 *
 * knet_h   - pointer to knet_handle_t
 *
 * enable   - set to 1 to allow data forwarding, 0 to disable data forwarding.
 *
 * knet_handle_setfwd returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 *
 * By default data forwarding is off and no traffic will pass through knet until
 * it is set on.
 */

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled);

/*
 * knet_handle_pmtud_setfreq
 *
 * knet_h   - pointer to knet_handle_t
 *
 * interval - define the interval in seconds between PMTUd scans
 *            range from 1 to 86400 (24h)
 *
 * knet_handle_pmtud_setfreq returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 *
 * default interval is 60.
 */

#define KNET_PMTUD_DEFAULT_INTERVAL 60

int knet_handle_pmtud_setfreq(knet_handle_t knet_h, unsigned int interval);

/*
 * knet_handle_pmtud_getfreq
 *
 * knet_h   - pointer to knet_handle_t
 *
 * interval - pointer where to store the current interval value
 *
 * knet_handle_pmtud_setfreq returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */


int knet_handle_pmtud_getfreq(knet_handle_t knet_h, unsigned int *interval);

/*
 * knet_handle_enable_pmtud_notify
 *
 * knet_h   - pointer to knet_handle_t
 *
 * pmtud_notify_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * pmtud_notify_fn
 *            is a callback function that is invoked every time
 *            a path MTU size change is detected.
 *            The function allows libknet to notify the user
 *            of data MTU, that's the max value that can be send
 *            onwire without fragmentation. The data MTU will always
 *            be lower than real link MTU because it accounts for
 *            protocol overhead, knet packet header and (if configured)
 *            crypto overhead,
 *            This function MUST NEVER block or add substantial delays.
 *
 * knet_handle_enable_pmtud_notify returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_enable_pmtud_notify(knet_handle_t knet_h,
			      void *pmtud_notify_fn_private_data,
			      void (*pmtud_notify_fn) (
					void *private_data,
					unsigned int data_mtu));

/*
 * knet_handle_pmtud_get
 *
 * knet_h   - pointer to knet_handle_t
 *
 * data_mtu - pointer where to store data_mtu (see above)
 *
 * knet_handle_pmtud_get returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_pmtud_get(knet_handle_t knet_h,
				unsigned int *data_mtu);

/*
 * knet_handle_crypto
 *
 * knet_h   - pointer to knet_handle_t
 *
 * knet_handle_crypto_cfg -
 *            pointer to a knet_handle_crypto_cfg structure
 *
 *            crypto_model should contain the model name.
 *                         Currently only "nss" is supported.
 *                         Setting to "none" will disable crypto.
 *
 *            crypto_cipher_type
 *                         should contain the cipher algo name.
 *                         It can be set to "none" to disable
 *                         encryption.
 *                         Currently supported by "nss" model:
 *                         "3des", "aes128", "aes192" and "aes256".
 *
 *            crypto_hash_type
 *                         should contain the hashing algo name.
 *                         It can be set to "none" to disable
 *                         hashing.
 *                         Currently supported by "nss" model:
 *                         "md5", "sha1", "sha256", "sha384" and "sha512".
 *
 *            private_key  will contain the private shared key.
 *                         It has to be at least KNET_MIN_KEY_LEN long.
 *
 *            private_key_len
 *                         length of the provided private_key.
 *
 * Implementation notes/current limitations:
 * - enabling crypto, will increase latency as packets have
 *   to processed.
 * - enabling crypto might reduce the overall throughtput
 *   due to crypto data overhead.
 * - re-keying is not implemented yet.
 * - private/public key encryption/hashing is not currently
 *   planned.
 * - crypto key must be the same for all hosts in the same
 *   knet instance.
 * - it is safe to call knet_handle_crypto multiple times at runtime.
 *   The last config will be used.
 *   IMPORTANT: a call to knet_handle_crypto can fail due to:
 *              1) failure to obtain locking
 *              2) errors to initializing the crypto level.
 *   This can happen even in subsequent calls to knet_handle_crypto.
 *   A failure in crypto init, might leave your traffic unencrypted!
 *   It's best to stop data forwarding (see above), change crypto config,
 *   start forward again.
 *
 * knet_handle_crypto returns:
 *
 * 0 on success
 * -1 on locking error and errno is set.
 * -2 on crypto initialization error. No errno is provided at the moment.
 */

#define KNET_MIN_KEY_LEN 1024
#define KNET_MAX_KEY_LEN 4096

struct knet_handle_crypto_cfg {
	char		crypto_model[16];
	char		crypto_cipher_type[16];
	char		crypto_hash_type[16];
	unsigned char	private_key[KNET_MAX_KEY_LEN];
	unsigned int	private_key_len;
};

int knet_handle_crypto(knet_handle_t knet_h,
		       struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

/*
 * host structs/API calls
 */

/*
 * knet_host_add
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new documentation above)
 *
 * knet_host_add returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_add(knet_handle_t knet_h, uint16_t host_id);

/*
 * knet_host_remove
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new documentation above)
 *
 * knet_host_remove returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_remove(knet_handle_t knet_h, uint16_t host_id);

/*
 * knet_host_set_name
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see above
 *
 * name     - this name will be used for pretty logging and eventually
 *            search for hosts (see also get_name and get_id below).
 *            Only up to KNET_MAX_HOST_LEN - 1 bytes will be copied.
 *            name has to be unique for each host.
 *
 * knet_host_set_name returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_set_name(knet_handle_t knet_h, uint16_t host_id,
		       const char *name);

/*
 * knet_host_get_name_by_host_id
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see above
 *
 * name     - pointer to a preallocated buffer of at least size KNET_MAX_HOST_LEN
 *            where the current host name will be stored
 *            (as set by knet_host_set_name or default by knet_host_add)
 *
 * knet_host_get_name_by_host_id returns:
 *
 * 1 if host is found and name is valid
 * 0 if host is not found. name is left untouched.
 * -1 on error and errno is set.
 */

int knet_host_get_name_by_host_id(knet_handle_t knet_h, uint16_t host_id,
				  char *name);

/*
 * knet_host_get_id_by_host_name
 *
 * knet_h   - pointer to knet_handle_t
 *
 * name     - name to lookup, max len KNET_MAX_HOST_LEN
 *
 * host_id  - where to store the result
 *
 * knet_host_get_id_by_host_name returns:
 *
 * 1 if host is found and name is valid
 * 0 if host is not found. name is left untouched.
 * -1 on error and errno is set.
 */

int knet_host_get_id_by_host_name(knet_handle_t knet_h, const char *name,
				  uint16_t *host_id);

/*
 * knet_host_get_host_list
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_ids - array of at lest KNET_MAX_HOST size
 *
 * host_ids_entries -
 *            number of entries writted in host_ids
 *
 * knet_host_get_host_list returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_host_list(knet_handle_t knet_h,
			    uint16_t *host_ids, size_t *host_ids_entries);

/*
 * define switching policies
 */

#define KNET_LINK_POLICY_PASSIVE 0
#define KNET_LINK_POLICY_ACTIVE  1
#define KNET_LINK_POLICY_RR      2

/*
 * knet_host_set_policy
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see above
 *
 * policy   - there are currently 3 kind of simple switching policies
 *            as defined above, based on link configuration.
 *            KNET_LINK_POLICY_PASSIVE - the active link with the lowest
 *                                       priority will be used.
 *                                       if one or more active links share
 *                                       the same priority, the one with
 *                                       lowest link_id will be used.
 *
 *            KNET_LINK_POLICY_ACTIVE  - all active links will be used
 *                                       simultaneously to send traffic.
 *                                       link priority is ignored.
 *
 *            KNET_LINK_POLICY_RR      - round-robin policy, every packet
 *                                       will be send on a different active
 *                                       link.
 *
 * knet_host_set_policy returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_set_policy(knet_handle_t knet_h, uint16_t host_id,
			 int policy);

/*
 * knet_host_get_policy
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see above
 *
 * policy   - will contain the current configured switching policy.
 *            Default is passive when creating a new host.
 *
 * knet_host_get_policy returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_policy(knet_handle_t knet_h, uint16_t host_id,
			 int *policy);

/*
 * knet_host_enable_status_change_notify
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_status_change_notify_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * host_status_change_notify_fn
 *            is a callback function that is invoked every time
 *            there is a change in the host status.
 *            host status is identified by:
 *            - reachable, this host can send/receive data to/from host_id
 *            - remote, 0 if the host_id is connected locally or 1 if
 *                      the there is one or more knet host(s) in between.
 *                      NOTE: re-switching is NOT currently implemented,
 *                            but this is ready for future and can avoid
 *                            an API/ABI breakage later on.
 *            - external, 0 if the host_id is configured locally or 1 if
 *                        it has been added from remote nodes config.
 *                        NOTE: dynamic topology is NOT currently implemented,
 *                        but this is ready for future and can avoid
 *                        an API/ABI breakage later on.
 *            This function MUST NEVER block or add substantial delays.
 *
 * knet_host_status_change_notify returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_enable_status_change_notify(knet_handle_t knet_h,
					  void *host_status_change_notify_fn_private_data,
					  void (*host_status_change_notify_fn) (
						void *private_data,
						uint16_t host_id,
						uint8_t reachable,
						uint8_t remote,
						uint8_t external));

/*
 * define host status structure for quick lookup
 * struct is in flux as more stats will be added soon
 *
 * reachable             host_id can be seen either directly connected
 *                       or via another host_id
 *
 * remote                0 = node is connected locally, 1 is visible via
 *                       via another host_id
 *
 * external              0 = node is configured/known locally,
 *                       1 host_id has been received via another host_id
 */

struct knet_host_status {
	uint8_t reachable;
	uint8_t remote;
	uint8_t external;
	/* add host statistics */
};

/*
 * knet_host_status_get
 *
 * knet_h   - pointer to knet_handle_t
 *
 * status    - pointer to knet_host_status struct (see above)
 *
 * knet_handle_pmtud_get returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_status(knet_handle_t knet_h, uint16_t host_id,
			 struct knet_host_status *status);

/*
 * link structs/API calls
 *
 * every host allocated/managed by knet_host_* has
 * KNET_MAX_LINK structures to define the network
 * paths that connect 2 hosts.
 *
 * Each link is identified by a link_id that has a
 * values between 0 and KNET_MAX_LINK - 1.
 *
 * KNOWN LIMITATIONS:
 *
 * - let's assume the scenario where two hosts are connected
 *   with any number of links. link_id must match on both sides.
 *   If host_id 0 link_id 0 is configured to connect IP1 to IP2 and
 *   host_id 0 link_id 1 is configured to connect IP3 to IP4,
 *   host_id 1 link_id 0 _must_ connect IP2 to IP1 and likewise
 *   host_id 1 link_id 1 _must_ connect IP4 to IP3.
 *   We might be able to lift this restriction in future, by using
 *   other data to determine src/dst link_id, but for now, deal with it.
 *
 * -
 */

/*
 * knet_link_set_config
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *             this can be null if we don't know the incoming
 *             IP address/port and the link will remain quiet
 *             till the node on the other end will initiate a
 *             connection
 *
 * knet_link_set_config returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr);

/*
 * knet_link_get_config
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *             this can be null if the link has dynamic incoming connection
 *
 * knet_link_set_config returns:
 *
 * 1 on success and the link is dynamic, dst_addr is unknown/unconfigured
 * 0 on success and both src and dst have been configured by set_config
 * -1 on error and errno is set.
 */

int knet_link_get_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr);

/*
 * knet_link_set_enable
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * knet_link_set_enable returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 unsigned int enabled);

/*
 * knet_link_get_enable
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * knet_link_get_enable returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 unsigned int *enabled);

/*
 * knet_link_set_pong_count
 *
 * knet_h     - pointer to knet_handle_t
 *
 * host_id    - see above
 *
 * link_id    - see above
 *
 * pong_count - how many valid ping/pongs before a link is marked UP.
 *              default: 5, value should be > 0
 *
 * knet_link_set_pong_count returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_pong_count(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			     uint8_t pong_count);

/*
 * knet_link_get_pong_count
 *
 * knet_h     - pointer to knet_handle_t
 *
 * host_id    - see above
 *
 * link_id    - see above
 *
 * pong_count - see above
 *
 * knet_link_get_pong_count returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_pong_count(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			     uint8_t *pong_count);

/*
 * knet_link_set_timeout
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * interval  - specify the ping interval
 *
 * timeout   - if no pong is received within this time,
 *             the link is declared dead
 *
 * precision - how many values of latency are used to calculate
 *             the average link latency (see also get_status below)
 *
 * knet_link_set_timeout returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_timeout(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			  time_t interval, time_t timeout, unsigned int precision);

/*
 * knet_link_get_timeout
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * interval  - ping intervall
 *
 * timeout   - if no pong is received within this time,
 *             the link is declared dead
 *
 * precision - how many values of latency are used to calculate
 *             the average link latency (see also get_status below)
 *
 * knet_link_get_timeout returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_timeout(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			  time_t *interval, time_t *timeout, unsigned int *precision);

/*
 * knet_link_set_priority
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * priority  - specify the switching priority for this link
 *             see also knet_host_set_policy
 *
 * knet_link_set_priority returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_priority(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			   uint8_t priority);

/*
 * knet_link_get_priority
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * priority  - gather the switching priority for this link
 *             see also knet_host_set_policy
 *
 * knet_link_get_priority returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_priority(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			   uint8_t *priority);

/*
 * knet_link_get_link_list
 *
 * knet_h   - pointer to knet_handle_t
 *
 * link_ids - array of at lest KNET_MAX_LINK size
 *            with the list of configured links for a certain host.
 *
 * link_ids_entries -
 *            number of entries contained in link_ids
 *
 * knet_link_get_link_list returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_link_list(knet_handle_t knet_h, uint16_t host_id,
			    uint8_t *link_ids, size_t *link_ids_entries);

/*
 * define link status structure for quick lookup
 * struct is in flux as more stats will be added soon
 *
 * src/dst_{ipaddr,port} strings are filled by
 *                       getnameinfo(3) when configuring the link.
 *                       if the link is dynamic (see knet_link_set_config)
 *                       dst_ipaddr/port will contain ipaddr/port of the currently
 *                       connected peer or "Unknown" if it was not possible
 *                       to determine the ipaddr/port at runtime.
 *
 * enabled               see also knet_link_set/get_enable.
 *
 * connected             the link is connected to a peer and ping/pong traffic
 *                       is flowing.
 *
 * dynconnected          the link has dynamic ip on the other end, and
 *                       we can see the other host is sending pings to us.
 *
 * latency               average latency of this link
 *                       see also knet_link_set/get_timeout.
 *
 * pong_last             if the link is down, this value tells us how long
 *                       ago this link was active. A value of 0 means that the link
 *                       has never been active.
 */

struct knet_link_status {
	char src_ipaddr[KNET_MAX_HOST_LEN];
	char src_port[KNET_MAX_PORT_LEN];
	char dst_ipaddr[KNET_MAX_HOST_LEN];
	char dst_port[KNET_MAX_PORT_LEN];
	unsigned int enabled:1;		/* link is configured and admin enabled for traffic */
	unsigned int connected:1;       /* link is connected for data (local view) */
	unsigned int dynconnected:1;	/* link has been activated by remote dynip */
	unsigned long long latency;	/* average latency computed by fix/exp */
	struct timespec pong_last;
	unsigned int mtu;		/* current detected MTU on this link */
	unsigned int proto_overhead;    /* contains the size of the IP protocol, knet headers and
					 * crypto headers (if configured). This value is filled in
					 * ONLY after the first PMTUd run on that given link,
					 * and can change if link configuration or crypto configuration
					 * changes at runtime.
					 * WARNING: in general mtu + proto_overhead might or might
					 * not match the output of ifconfig mtu due to crypto
					 * requirements to pad packets to some specific boundaries. */
	/* add link statistics */
};

/*
 * knet_link_get_status
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see above
 *
 * link_id   - see above
 *
 * status    - pointer to knet_link_status struct (see above)
 *
 * knet_link_get_status returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_status(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct knet_link_status *status);

/*
 * logging structs/API calls
 */

/*
 * libknet is composed of several subsystems. In order
 * to easily distinguish log messages coming from different
 * places, each subsystem has its own ID.
 */

#define KNET_SUB_COMMON      0 /* common.c */
#define KNET_SUB_HANDLE      1 /* handle.c alloc/dealloc config changes */
#define KNET_SUB_HOST        2 /* host add/del/modify */
#define KNET_SUB_LISTENER    3 /* listeners add/del/modify... */
#define KNET_SUB_LINK        4 /* link add/del/modify */
#define KNET_SUB_PMTUD       5 /* Path MTU Discovery */
#define KNET_SUB_SEND_T      6 /* send to link thread */
#define KNET_SUB_LINK_T      7 /* recv from link thread */
#define KNET_SUB_SWITCH_T    8 /* switching thread */
#define KNET_SUB_HB_T        9 /* heartbeat thread */
#define KNET_SUB_PMTUD_T    10 /* Path MTU Discovery thread */
#define KNET_SUB_FILTER     11 /* (ether)filter errors */
#define KNET_SUB_CRYPTO     12 /* crypto.c generic layer */
#define KNET_SUB_NSSCRYPTO  13 /* nsscrypto.c */
#define KNET_SUB_LAST       KNET_SUB_NSSCRYPTO
#define KNET_MAX_SUBSYSTEMS KNET_SUB_LAST + 1

/*
 * Convert between subsystem IDs and names
 */

/*
 * knet_log_get_subsystem_name
 *
 * return internal name of the subsystem or "unknown"
 */

const char *knet_log_get_subsystem_name(uint8_t subsystem);

/*
 * knet_log_get_subsystem_id
 *
 * return internal ID of the subsystem or KNET_SUB_COMMON
 */

uint8_t knet_log_get_subsystem_id(const char *name);

/*
 * 4 log levels are enough for everybody
 */

#define KNET_LOG_ERR         0 /* unrecoverable errors/conditions */
#define KNET_LOG_WARN        1 /* recoverable errors/conditions */
#define KNET_LOG_INFO        2 /* info, link up/down, config changes.. */
#define KNET_LOG_DEBUG       3

/*
 * Convert between log level values and names
 */

/*
 * knet_log_get_loglevel_name
 *
 * return internal name of the log level or "unknown"
 */

const char *knet_log_get_loglevel_name(uint8_t level);

/*
 * knet_log_get_loglevel_id
 *
 * return internal ID of the subsystem or KNET_SUB_COMMON
 */

uint8_t knet_log_get_loglevel_id(const char *name);

/*
 * every log message is composed by a text message (including a trailing \n)
 * and message level/subsystem IDs.
 * In order to make debugging easier it is possible to send those packets
 * straight to stdout/stderr (see ping_test.c stdout option).
 */

#define KNET_MAX_LOG_MSG_SIZE    256

struct knet_log_msg {
	char	msg[KNET_MAX_LOG_MSG_SIZE - (sizeof(uint8_t)*2)];
	uint8_t	subsystem;	/* KNET_SUB_* */
	uint8_t msglevel;	/* KNET_LOG_* */
};

/*
 * knet_log_set_log_level
 *
 * knet_h     - same as above
 *
 * subsystem  - same as above
 *
 * level      - same as above
 *
 * knet_log_set_loglevel allows fine control of log levels by subsystem.
 *                       See also knet_handle_new for defaults.
 *
 * knet_log_set_loglevel returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_log_set_loglevel(knet_handle_t knet_h, uint8_t subsystem,
			  uint8_t level);

/*
 * knet_log_get_log_level
 *
 * knet_h     - same as above
 *
 * subsystem  - same as above
 *
 * level      - same as above
 *
 * knet_log_get_loglevel returns:
 *
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_log_get_loglevel(knet_handle_t knet_h, uint8_t subsystem,
			  uint8_t *level);

#endif
