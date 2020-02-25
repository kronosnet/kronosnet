/*
 * Copyright (C) 2010-2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __LIBKNET_H__
#define __LIBKNET_H__

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <limits.h>

/**
 * @file libknet.h
 * @brief kronosnet API include file
 * @copyright Copyright (C) 2010-2020 Red Hat, Inc.  All rights reserved.
 *
 * Kronosnet is an advanced VPN system for High Availability applications.
 */

#define KNET_API_VER 2

/*
 * libknet limits
 */

/*
 * Maximum number of hosts
 */

typedef uint16_t knet_node_id_t;

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

#define KNET_MAX_HOST_LEN 256
#define KNET_MAX_PORT_LEN 6

/*
 * Some notifications can be generated either on TX or RX
 */

#define KNET_NOTIFY_TX 0
#define KNET_NOTIFY_RX 1

/*
 * Link flags
 */

/*
 * Where possible, set traffic priority to high.
 * On Linux this sets the TOS to INTERACTIVE (6),
 * see tc-prio(8) for more infomation
 */

#define KNET_LINK_FLAG_TRAFFICHIPRIO (1ULL << 0)

/*
 * Handle flags
 */

/*
 * Use privileged operations during socket setup.
 */

#define KNET_HANDLE_FLAG_PRIVILEGED (1ULL << 0)

/*
 * threads timer resolution (see knet_handle_set_threads_timer_res below)
 */

#define KNET_THREADS_TIMER_RES 200000

typedef struct knet_handle *knet_handle_t;

/*
 * Handle structs/API calls
 */

/**
 * knet_handle_new
 *
 * @brief create a new instance of a knet handle
 *
 * host_id  - Each host in a knet is identified with a unique
 *            ID. when creating a new handle local host_id
 *            must be specified (0 to UINT16_MAX are all valid).
 *            It is the user's responsibility to check that the value
 *            is unique, or bad things might happen.
 *
 * log_fd   - Write file descriptor. If set to a value > 0, it will be used
 *            to write log packets from libknet to the application.
 *            Setting to 0 will disable logging from libknet.
 *            It is possible to enable logging at any given time (see logging API).
 *            Make sure to either read from this filedescriptor properly and/or
 *            mark it O_NONBLOCK, otherwise if the fd becomes full, libknet could
 *            block.
 *            It is strongly encouraged to use pipes (ex: pipe(2) or pipe2(2)) for
 *            logging fds due to the atomic nature of writes between fds.
 *            See also libknet test suite for reference and guidance.
 *
 * default_log_level -
 *            If logfd is specified, it will initialize all subsystems to log
 *            at default_log_level value. (see logging API)
 *
 * flags    - bitwise OR of some of the following flags:
 *            KNET_HANDLE_FLAG_PRIVILEGED: use privileged operations setting up the
 *            communication sockets.  If disabled, failure to acquire large
 *            enough socket buffers is ignored but logged.  Inadequate buffers
 *            lead to poor performance.
 *
 * @return
 * on success, a new knet_handle_t is returned.
 * on failure, NULL is returned and errno is set.
 * knet-specific errno values:
 *   ENAMETOOLONG - socket buffers couldn't be set big enough and KNET_HANDLE_FLAG_PRIVILEGED was specified
 *   ERANGE       - buffer size readback returned unexpected type
 */

knet_handle_t knet_handle_new(knet_node_id_t host_id,
			      int log_fd,
			      uint8_t default_log_level,
			      uint64_t flags);

/**
 * knet_handle_free
 *
 * @brief Destroy a knet handle, free all resources
 *
 * knet_h   - pointer to knet_handle_t
 *
 * @return
 * knet_handle_free returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_free(knet_handle_t knet_h);

/**
 * knet_handle_set_threads_timer_res
 *
 * @brief Change internal thread timer resolution
 *
 * knet_h   - pointer to knet_handle_t
 *
 * timeres  - some threads inside knet will use usleep(timeres)
 *            to check if any activity has to be performed, or wait
 *            for the next cycle. 'timeres' (expressed in nano seconds)
 *            defines this interval, with a default of KNET_THREADS_TIMER_RES
 *            (200000).
 *            The lower this value is, the more often knet will perform
 *            those checks and allows a more (time) precise execution of
 *            some operations (for example ping/pong), at the cost of higher
 *            CPU usage.
 *            Accepted values:
 *            0 - reset timer res to default
 *            1 - 999 invalid (as it would cause 100% CPU spinning on some
 *                    epoll operations)
 *            1000 or higher - valid
 *
 * Unless you know exactly what you are doing, stay away from
 * changing the default or seek written and notarized approval
 * from the knet developer team.
 *
 * @return
 * knet_handle_set_threads_timer_res returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_set_threads_timer_res(knet_handle_t knet_h,
				      useconds_t timeres);

/**
 * knet_handle_get_threads_timer_res
 *
 * @brief Get internal thread timer resolutions
 *
 * knet_h   - pointer to knet_handle_t
 *
 * timeres  - current timer res value
 *
 * @return
 * knet_handle_set_threads_timer_res returns
 * 0 on success and timerres will contain the current value
 * -1 on error and errno is set.
 */

int knet_handle_get_threads_timer_res(knet_handle_t knet_h,
				      useconds_t *timeres);

/**
 * knet_handle_enable_sock_notify
 *
 * @brief Register a callback to receive socket events
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
 * @return
 * knet_handle_enable_sock_notify returns
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

#define KNET_DATAFD_MAX 32

/**
 * knet_handle_add_datafd
 *
 * @brief Install a file descriptor for communication
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
 *            User provided datafd will be marked as non-blocking and close-on-exec.
 *
 * *channel - This value is analogous to the tag in VLAN tagging.
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
 * @return
 * knet_handle_add_datafd returns
 * @retval 0 on success,
 *         *datafd  will be populated with a socket if the original value was 0
 *            or if a specific fd was set, the value is untouched.
 *         *channel will be populated with a channel number if the original value
 *            was negative or the value is untouched if a specific channel
 *            was requested.
 *
 * @retval -1 on error and errno is set.
 *         *datafd and *channel are untouched or empty.
 */

int knet_handle_add_datafd(knet_handle_t knet_h, int *datafd, int8_t *channel);

/**
 * knet_handle_remove_datafd
 *
 * @brief Remove a file descriptor from knet
 *
 * knet_h   - pointer to knet_handle_t
 *
 * datafd   - file descriptor to remove.
 *            NOTE that if the socket/fd was created by knet_handle_add_datafd,
 *                 the socket will be closed by libknet.
 *
 * @return
 * knet_handle_remove_datafd returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_remove_datafd(knet_handle_t knet_h, int datafd);

/**
 * knet_handle_get_channel
 *
 * @brief Get the channel associated with a file descriptor
 *
 * knet_h  - pointer to knet_handle_t
 *
 * datafd  - get the channel associated to this datafd
 *
 * *channel - will contain the result
 *
 * @return
 * knet_handle_get_channel returns
 * @retval 0 on success
 *   and *channel will contain the result
 * @retval -1 on error and errno is set.
 *   and *channel content is meaningless
 */

int knet_handle_get_channel(knet_handle_t knet_h, const int datafd, int8_t *channel);

/**
 * knet_handle_get_datafd
 *
 * @brief Get the file descriptor associated with a channel
 *
 * knet_h   - pointer to knet_handle_t
 *
 * channel  - get the datafd associated to this channel
 *
 * *datafd  - will contain the result
 *
 * @return
 * knet_handle_get_datafd returns
 * @retval 0 on success
 *   and *datafd will contain the results
 * @retval -1 on error and errno is set.
 *   and *datafd content is meaningless
 */

int knet_handle_get_datafd(knet_handle_t knet_h, const int8_t channel, int *datafd);

/**
 * knet_recv
 *
 * @brief Receive data from knet nodes
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to buffer to store the received data
 *
 * buff_len - buffer length
 *
 * channel  - channel number
 *
 * @return
 * knet_recv is a commodity function to wrap iovec operations
 * around a socket. It returns a call to readv(2).
 */

ssize_t knet_recv(knet_handle_t knet_h,
		  char *buff,
		  const size_t buff_len,
		  const int8_t channel);

/**
 * knet_send
 *
 * @brief Send data to knet nodes
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to the buffer of data to send
 *
 * buff_len - length of data to send
 *
 * channel  - channel number
 *
 * @return
 * knet_send is a commodity function to wrap iovec operations
 * around a socket. It returns a call to writev(2).
 */

ssize_t knet_send(knet_handle_t knet_h,
		  const char *buff,
		  const size_t buff_len,
		  const int8_t channel);

/**
 * knet_send_sync
 *
 * @brief Synchronously send data to knet nodes
 *
 * knet_h   - pointer to knet_handle_t
 *
 * buff     - pointer to the buffer of data to send
 *
 * buff_len - length of data to send
 *
 * channel  - data channel to use (see knet_handle_add_datafd(3))
 *
 * All knet RX/TX operations are async for performance reasons.
 * There are applications that might need a sync version of data
 * transmission and receive errors in case of failure to deliver
 * to another host.
 * knet_send_sync bypasses the whole TX async layer and delivers
 * data directly to the link layer, and returns errors accordingly.
 * knet_send_sync sends only one packet to one host at a time.
 * It does NOT support multiple destinations or multicast packets.
 * Decision is still based on dst_host_filter_fn.
 *
 * @return
 * knet_send_sync returns 0 on success and -1 on error.
 * In addition to normal sendmmsg errors, knet_send_sync can fail
 * due to:
 *
 * @retval ECANCELED - data forward is disabled
 * @retval EFAULT    - dst_host_filter fatal error
 * @retval EINVAL    - dst_host_filter did not provide dst_host_ids_entries on unicast pckts
 * @retval E2BIG     - dst_host_filter did return more than one dst_host_ids_entries on unicast pckts
 * @retval ENOMSG    - received unknown message type
 * @retval EHOSTDOWN - unicast pckt cannot be delivered because dest host is not connected yet
 * @retval ECHILD    - crypto failed
 * @retval EAGAIN    - sendmmsg was unable to send all messages and there was no progress during retry
 */

int knet_send_sync(knet_handle_t knet_h,
		   const char *buff,
		   const size_t buff_len,
		   const int8_t channel);

/**
 * knet_handle_enable_filter
 *
 * @brief install a filter to route packets
 *
 * knet_h   - pointer to knet_handle_t
 *
 * dst_host_filter_fn_private_data
 *            void pointer to data that can be used to identify
 *            the callback.
 *
 * dst_host_filter_fn -
 *            is a callback function that is invoked every time
 *            a packet hits datafd (see knet_handle_new(3)).
 *            the function allows users to tell libknet where the
 *            packet has to be delivered.
 *
 *            const unsigned char *outdata - is a pointer to the
 *                                           current packet
 *            ssize_t outdata_len          - length of the above data
 *            uint8_t tx_rx                - filter is called on tx or rx
 *                                           (KNET_NOTIFY_TX, KNET_NOTIFY_RX)
 *            knet_node_id_t this_host_id  - host_id processing the packet
 *            knet_node_id_t src_host_id   - host_id that generated the
 *                                           packet
 *            knet_node_id_t *dst_host_ids - array of KNET_MAX_HOST knet_node_id_t
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
 * @return
 * knet_handle_enable_filter returns
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
					knet_node_id_t this_host_id,
					knet_node_id_t src_host_id,
					int8_t *channel,
					knet_node_id_t *dst_host_ids,
					size_t *dst_host_ids_entries));

/**
 * knet_handle_setfwd
 *
 * @brief Start packet forwarding
 *
 * knet_h   - pointer to knet_handle_t
 *
 * enable   - set to 1 to allow data forwarding, 0 to disable data forwarding.
 *
 * @return
 * knet_handle_setfwd returns
 * 0 on success
 * -1 on error and errno is set.
 *
 * By default data forwarding is off and no traffic will pass through knet until
 * it is set on.
 */

int knet_handle_setfwd(knet_handle_t knet_h, unsigned int enabled);

/**
 * knet_handle_enable_access_lists
 *
 * @brief Enable or disable usage of access lists (default: off)
 *
 * knet_h   - pointer to knet_handle_t
 *
 * enable   - set to 1 to use access lists, 0 to disable access_lists.
 *
 * @return
 * knet_handle_enable_access_lists returns
 * 0 on success
 * -1 on error and errno is set.
 *
 * access lists are bound to links. There are 2 types of links:
 * 1) point to point, where both source and destinations are well known
 *    at configuration time.
 * 2) open links, where only the source is known at configuration time.
 *
 * knet will automatically generate access lists for point to point links.
 *
 * For open links, knet provides 4 API calls to manipulate access lists:
 * knet_link_add_acl(3), knet_link_rm_acl(3), knet_link_insert_acl(3)
 * and knet_link_clear_acl(3).
 * Those API calls will work exclusively on open links as they
 * are of no use on point to point links.
 *
 * knet will not enforce any access list unless specifically enabled by
 * knet_handle_enable_access_lists(3).
 *
 * From a security / programming perspective we recommend:
 * - create the knet handle
 * - enable access lists
 * - configure hosts and links
 * - configure access lists for open links
 */

int knet_handle_enable_access_lists(knet_handle_t knet_h, unsigned int enabled);

#define KNET_PMTUD_DEFAULT_INTERVAL 60

/**
 * knet_handle_pmtud_setfreq
 *
 * @brief Set the interval between PMTUd scans
 *
 * knet_h   - pointer to knet_handle_t
 *
 * interval - define the interval in seconds between PMTUd scans
 *            range from 1 to 86400 (24h)
 *
 * @return
 * knet_handle_pmtud_setfreq returns
 * 0 on success
 * -1 on error and errno is set.
 *
 * default interval is 60.
 */

int knet_handle_pmtud_setfreq(knet_handle_t knet_h, unsigned int interval);

/**
 * knet_handle_pmtud_getfreq
 *
 * @brief Get the interval between PMTUd scans
 *
 * knet_h   - pointer to knet_handle_t
 *
 * interval - pointer where to store the current interval value
 *
 * @return
 * knet_handle_pmtud_setfreq returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_pmtud_getfreq(knet_handle_t knet_h, unsigned int *interval);

/**
 * knet_handle_enable_pmtud_notify
 *
 * @brief install a callback to receive PMTUd changes
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
 * @return
 * knet_handle_enable_pmtud_notify returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_enable_pmtud_notify(knet_handle_t knet_h,
				    void *pmtud_notify_fn_private_data,
				    void (*pmtud_notify_fn) (
						void *private_data,
						unsigned int data_mtu));

/**
 * knet_handle_pmtud_set
 *
 * @brief Set the current interface MTU
 *
 * knet_h    - pointer to knet_handle_t
 *
 * iface_mtu - current interface MTU, value 0 to 65535. 0 will
 *             re-enable automatic MTU discovery.
 *             In a setup with multiple interfaces, please specify
 *             the lowest MTU between the selected intefaces.
 *             knet will automatically adjust this value for
 *             all headers overhead and set the correct data_mtu.
 *             data_mtu can be retrivied with knet_handle_pmtud_get(3)
 *             or applications will receive a pmtud_nofity event
 *             if enabled via knet_handle_enable_pmtud_notify(3).
 *
 * @return
 * knet_handle_pmtud_set returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_pmtud_set(knet_handle_t knet_h,
			  unsigned int iface_mtu);

/**
 * knet_handle_pmtud_get
 *
 * @brief Get the current data MTU
 *
 * knet_h   - pointer to knet_handle_t
 *
 * data_mtu - pointer where to store data_mtu
 *
 * @return
 * knet_handle_pmtud_get returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_pmtud_get(knet_handle_t knet_h,
				unsigned int *data_mtu);


#define KNET_MIN_KEY_LEN  128
#define KNET_MAX_KEY_LEN 4096

struct knet_handle_crypto_cfg {
	char		crypto_model[16];
	char		crypto_cipher_type[16];
	char		crypto_hash_type[16];
	unsigned char	private_key[KNET_MAX_KEY_LEN];
	unsigned int	private_key_len;
};

/**
 * knet_handle_crypto
 *
 * @brief set up packet cryptographic signing & encryption
 *
 * knet_h   - pointer to knet_handle_t
 *
 * knet_handle_crypto_cfg -
 *            pointer to a knet_handle_crypto_cfg structure
 *
 *            crypto_model should contain the model name.
 *                         Currently only "openssl" and "nss" are supported.
 *                         Setting to "none" will disable crypto.
 *
 *            crypto_cipher_type
 *                         should contain the cipher algo name.
 *                         It can be set to "none" to disable
 *                         encryption.
 *                         Currently supported by "nss" model:
 *                         "aes128", "aes192" and "aes256".
 *                         "openssl" model supports more modes and it strictly
 *                         depends on the openssl build. See: EVP_get_cipherbyname
 *                         openssl API call for details.
 *
 *            crypto_hash_type
 *                         should contain the hashing algo name.
 *                         It can be set to "none" to disable
 *                         hashing.
 *                         Currently supported by "nss" model:
 *                         "md5", "sha1", "sha256", "sha384" and "sha512".
 *                         "openssl" model supports more modes and it strictly
 *                         depends on the openssl build. See: EVP_get_digestbyname
 *                         openssl API call for details.
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
 *   A failure in crypto init will restore the previous crypto configuration.
 *
 * @return
 * knet_handle_crypto returns:
 * @retval 0 on success
 * @retval -1 on error and errno is set.
 * @retval -2 on crypto subsystem initialization error. No errno is provided at the moment (yet).
 */

int knet_handle_crypto(knet_handle_t knet_h,
		       struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);



#define KNET_COMPRESS_THRESHOLD 100

struct knet_handle_compress_cfg {
	char	 compress_model[16];
	uint32_t compress_threshold;
	int	 compress_level;
};

/**
 * knet_handle_compress
 *
 * @brief Set up packet compression
 *
 * knet_h   - pointer to knet_handle_t
 *
 * knet_handle_compress_cfg -
 *            pointer to a knet_handle_compress_cfg structure
 *
 *            compress_model contains the model name.
 *                           See "compress_level" for the list of accepted values.
 *                           Setting the value to "none" disables compression.
 *
 *            compress_threshold
 *                           tells the transmission thread to NOT compress
 *                           any packets that are smaller than the value
 *                           indicated. Default 100 bytes.
 *                           Set to 0 to reset to the default.
 *                           Set to 1 to compress everything.
 *                           Max accepted value is KNET_MAX_PACKET_SIZE.
 *
 *            compress_level is the "level" parameter for most models:
 *                           zlib: 0 (no compression), 1 (minimal) .. 9 (max compression).
 *                           lz4: 1 (max compression)... 9 (fastest compression).
 *                           lz4hc: 1 (min compression) ... LZ4HC_MAX_CLEVEL (16) or LZ4HC_CLEVEL_MAX (12)
 *                                  depending on the version of lz4hc libknet was built with.
 *                           lzma: 0 (minimal) .. 9 (max compression)
 *                           bzip2: 1 (minimal) .. 9 (max compression)
 *                           For lzo2 it selects the algorithm to use:
 *                                 1  : lzo1x_1_compress (default)
 *                                 11 : lzo1x_1_11_compress
 *                                 12 : lzo1x_1_12_compress
 *                                 15 : lzo1x_1_15_compress
 *                                 999: lzo1x_999_compress
 *                                 Other values select the default algorithm.
 *                           Please refer to the documentation of the respective
 *                           compression library for guidance about setting this
 *                           value.
 *
 * Implementation notes:
 * - it is possible to enable/disable compression at any time.
 * - nodes can be using a different compression algorithm at any time.
 * - knet does NOT implement the compression algorithm directly. it relies
 *   on external libraries for this functionality. Please read
 *   the libraries man pages to figure out which algorithm/compression
 *   level is best for the data you are planning to transmit.
 *
 * @return
 * knet_handle_compress returns
 * 0 on success
 * -1 on error and errno is set. EINVAL means that either the model or the
 *    level are not supported.
 */

int knet_handle_compress(knet_handle_t knet_h,
			 struct knet_handle_compress_cfg *knet_handle_compress_cfg);



struct knet_handle_stats {
	size_t   size;

	uint64_t tx_uncompressed_packets;
	uint64_t tx_compressed_packets;
	uint64_t tx_compressed_original_bytes;
	uint64_t tx_compressed_size_bytes;
	uint64_t tx_compress_time_ave;
	uint64_t tx_compress_time_min;
	uint64_t tx_compress_time_max;
	uint64_t tx_failed_to_compress;
	uint64_t tx_unable_to_compress;

	uint64_t rx_compressed_packets;
	uint64_t rx_compressed_original_bytes;
	uint64_t rx_compressed_size_bytes;
	uint64_t rx_compress_time_ave;
	uint64_t rx_compress_time_min;
	uint64_t rx_compress_time_max;
	uint64_t rx_failed_to_decompress;

	/* Overhead times, measured in usecs */
	uint64_t tx_crypt_packets;
	uint64_t tx_crypt_byte_overhead;
	uint64_t tx_crypt_time_ave;
	uint64_t tx_crypt_time_min;
	uint64_t tx_crypt_time_max;

	uint64_t rx_crypt_packets;
	uint64_t rx_crypt_time_ave;
	uint64_t rx_crypt_time_min;
	uint64_t rx_crypt_time_max;
};

/**
 * knet_handle_get_stats
 *
 * @brief Get statistics for compression & crypto
 *
 * knet_h   - pointer to knet_handle_t
 *
 * knet_handle_stats
 *            pointer to a knet_handle_stats structure
 *
 * struct_size
 *            size of knet_handle_stats structure to allow
 *            for backwards compatibility. libknet will only
 *            copy this much data into the stats structure
 *            so that older callers will not get overflowed if
 *            new fields are added.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 *
 */

int knet_handle_get_stats(knet_handle_t knet_h, struct knet_handle_stats *stats, size_t struct_size);

/*
 * Tell knet_handle_clear_stats whether to clear just the handle stats
 * or all of them.
 */
#define KNET_CLEARSTATS_HANDLE_ONLY     1
#define KNET_CLEARSTATS_HANDLE_AND_LINK 2

/**
 * knet_handle_clear_stats
 *
 * @brief Clear knet stats, link and/or handle
 *
 * knet_h   - pointer to knet_handle_t
 *
 * clear_option -  Which stats to clear, must be one of
 *
 * KNET_CLEARSTATS_HANDLE_ONLY or
 * KNET_CLEARSTATS_HANDLE_AND_LINK
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 *
 */

int knet_handle_clear_stats(knet_handle_t knet_h, int clear_option);



struct knet_crypto_info {
	const char *name; /* openssl,nss,etc.. */
	uint8_t properties; /* currently unused */
	char pad[256];      /* currently unused */
};

/**
 * knet_get_crypto_list
 *
 * @brief Get a list of supported crypto libraries
 *
 * crypto_list  - array of struct knet_crypto_info *
 *                If NULL then only the number of structs is returned in crypto_list_entries
 *                to allow the caller to allocate sufficient space.
 *		  libknet does not allow more than 256 crypto methods at the moment.
 *		  it is safe to allocate 256 structs to avoid calling
 *		  knet_get_crypto_list twice.
 *
 * crypto_list_entries - returns the number of structs in crypto_list
 *
 * @return
 * knet_get_crypto_list returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_get_crypto_list(struct knet_crypto_info *crypto_list,
			 size_t *crypto_list_entries);



struct knet_compress_info {
	const char *name; /* bzip2, lz4, etc.. */
	uint8_t properties; /* currently unused */
	char pad[256];      /* currently unused */
};

/**
 * knet_get_compress_list
 *
 * @brief Get a list of support compression types
 *
 * compress_list - array of struct knet_compress_info *
 *		   If NULL then only the number of structs is returned in compress_list_entries
 *		   to allow the caller to allocate sufficient space.
 *		   libknet does not allow more than 256 compress methods at the moment.
 *		   it is safe to allocate 256 structs to avoid calling
 *		   knet_get_compress_list twice.
 *
 * compress_list_entries - returns the number of structs in compress_list
 *
 * @return
 * knet_get_compress_list returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_get_compress_list(struct knet_compress_info *compress_list,
			   size_t *compress_list_entries);

/*
 * host structs/API calls
 */

/**
 * knet_host_add
 *
 * @brief Add a new host ID to knet
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new(3))
 *
 * @return
 * knet_host_add returns:
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_add(knet_handle_t knet_h, knet_node_id_t host_id);

/**
 * knet_host_remove
 *
 * @brief Remove a host ID from knet
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - each host in a knet is identified with a unique ID
 *            (see also knet_handle_new(3))
 *
 * @return
 * knet_host_remove returns:
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_remove(knet_handle_t knet_h, knet_node_id_t host_id);

/**
 * knet_host_set_name
 *
 * @brief Set the name of a knet host
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see knet_host_add(3)
 *
 * name     - this name will be used for pretty logging and eventually
 *            search for hosts (see also knet_handle_host_get_name(2) and knet_handle_host_get_id(3)).
 *            Only up to KNET_MAX_HOST_LEN - 1 bytes will be accepted and
 *            name has to be unique for each host.
 *
 * @return
 * knet_host_set_name returns:
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_set_name(knet_handle_t knet_h, knet_node_id_t host_id,
		       const char *name);

/**
 * knet_host_get_name_by_host_id
 *
 * @brief Get the name of a host given its ID
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see knet_host_add(3)
 *
 * name     - pointer to a preallocated buffer of at least size KNET_MAX_HOST_LEN
 *            where the current host name will be stored
 *            (as set by knet_host_set_name or default by knet_host_add)
 *
 * @return
 * knet_host_get_name_by_host_id returns:
 * 0 on success
 * -1 on error and errno is set (name is left untouched)
 */

int knet_host_get_name_by_host_id(knet_handle_t knet_h, knet_node_id_t host_id,
				  char *name);

/**
 * knet_host_get_id_by_host_name
 *
 * @brief Get the ID of a host given its name
 *
 * knet_h   - pointer to knet_handle_t
 *
 * name     - name to lookup, max len KNET_MAX_HOST_LEN
 *
 * host_id  - where to store the result
 *
 * @return
 * knet_host_get_id_by_host_name returns:
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_id_by_host_name(knet_handle_t knet_h, const char *name,
				  knet_node_id_t *host_id);

/**
 * knet_host_get_host_list
 *
 * @brief Get a list of hosts known to knet
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_ids - array of at lest KNET_MAX_HOST size
 *
 * host_ids_entries -
 *            number of entries writted in host_ids
 *
 * @return
 * knet_host_get_host_list returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_host_list(knet_handle_t knet_h,
			    knet_node_id_t *host_ids, size_t *host_ids_entries);

/*
 * define switching policies
 */

#define KNET_LINK_POLICY_PASSIVE 0
#define KNET_LINK_POLICY_ACTIVE  1
#define KNET_LINK_POLICY_RR      2

/**
 * knet_host_set_policy
 *
 * @brief Set the switching policy for a host's links
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see knet_host_add(3)
 *
 * policy   - there are currently 3 kind of simple switching policies
 *            based on link configuration.
 *            KNET_LINK_POLICY_PASSIVE - the active link with the highest
 *                                       priority (highest number) will be used.
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
 * @return
 * knet_host_set_policy returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_set_policy(knet_handle_t knet_h, knet_node_id_t host_id,
			 uint8_t policy);

/**
 * knet_host_get_policy
 *
 * @brief Get the switching policy for a host's links
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see knet_host_add(3)
 *
 * policy   - will contain the current configured switching policy.
 *            Default is passive when creating a new host.
 *
 * @return
 * knet_host_get_policy returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_policy(knet_handle_t knet_h, knet_node_id_t host_id,
			 uint8_t *policy);

/**
 * knet_host_enable_status_change_notify
 *
 * @brief Install a callback to get host status change events
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_status_change_notify_fn_private_data -
 *            void pointer to data that can be used to identify
 *            the callback
 *
 * host_status_change_notify_fn -
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
 * @return
 * knet_host_status_change_notify returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_enable_status_change_notify(knet_handle_t knet_h,
					  void *host_status_change_notify_fn_private_data,
					  void (*host_status_change_notify_fn) (
						void *private_data,
						knet_node_id_t host_id,
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

/**
 * knet_host_get_status
 *
 * @brief Get the status of a host
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_id  - see knet_host_add(3)
 *
 * status   - pointer to knet_host_status struct
 *
 * @return
 * knet_handle_pmtud_get returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_host_get_status(knet_handle_t knet_h, knet_node_id_t host_id,
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
 */

/*
 * commodity functions to convert strings to sockaddr and viceversa
 */

/**
 * knet_strtoaddr
 *
 * @brief Convert a hostname string to an address
 *
 * host      - IPaddr/hostname to convert
 *             be aware only the first IP address will be returned
 *             in case a hostname resolves to multiple IP
 *
 * port      - port to connect to
 *
 * ss        - sockaddr_storage where to store the converted data
 *
 * sslen     - len of the sockaddr_storage
 *
 * @return
 * knet_strtoaddr returns same error codes as getaddrinfo
 *
 */

int knet_strtoaddr(const char *host, const char *port,
		   struct sockaddr_storage *ss, socklen_t sslen);

/**
 * knet_addrtostr
 *
 * @brief Convert an address to a host name
 *
 * ss        - sockaddr_storage to convert
 *
 * sslen     - len of the sockaddr_storage
 *
 * host      - IPaddr/hostname where to store data
 *             (recommended size: KNET_MAX_HOST_LEN)
 *
 * port      - port buffer where to store data
 *             (recommended size: KNET_MAX_PORT_LEN)
 *
 * @return
 * knet_strtoaddr returns same error codes as getnameinfo
 */

int knet_addrtostr(const struct sockaddr_storage *ss, socklen_t sslen,
		   char *addr_buf, size_t addr_buf_size,
		   char *port_buf, size_t port_buf_size);



#define KNET_TRANSPORT_LOOPBACK 0
#define KNET_TRANSPORT_UDP      1
#define KNET_TRANSPORT_SCTP     2
#define KNET_MAX_TRANSPORTS     UINT8_MAX

/*
 * The Loopback transport is only valid for connections to localhost, the host
 * with the same node_id specified in knet_handle_new(). Only one link of this
 * type is allowed. Data sent down a LOOPBACK link will be copied directly from
 * the knet send datafd to the knet receive datafd so the application must be set
 * up to take data from that socket at least as often as it is sent or deadlocks
 * could occur. If used, a LOOPBACK link must be the only link configured to the
 * local host.
 */

struct knet_transport_info {
	const char *name;   /* UDP/SCTP/etc... */
	uint8_t id;         /* value that can be used for link_set_config */
	uint8_t properties; /* currently unused */
	char pad[256];      /* currently unused */
};

/**
 * knet_get_transport_list
 *
 * @brief Get a list of the transports support by this build of knet
 *
 * transport_list         - an array of struct transport_info that must be
 *                          at least of size struct transport_info * KNET_MAX_TRANSPORTS
 *
 * transport_list_entries - pointer to a size_t where to store how many transports
 *                          are available in this build of libknet.
 *
 * @return
 * knet_get_transport_list returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_get_transport_list(struct knet_transport_info *transport_list,
			    size_t *transport_list_entries);

/**
 * knet_get_transport_name_by_id
 *
 * @brief Get a transport name from its ID number
 *
 * transport - one of the KNET_TRANSPORT_xxx constants
 *
 * @return
 * knet_get_transport_name_by_id returns:
 *
 * @retval pointer to the name on success or
 * @retval NULL on error and errno is set.
 */

const char *knet_get_transport_name_by_id(uint8_t transport);

/**
 * knet_get_transport_id_by_name
 *
 * @brief Get a transport ID from its name
 *
 * name      - transport name (UDP/SCTP/etc)
 *
 * @return
 * knet_get_transport_name_by_id returns:
 *
 * @retval KNET_MAX_TRANSPORTS on error and errno is set accordingly
 * @retval KNET_TRANSPORT_xxx on success.
 */

uint8_t knet_get_transport_id_by_name(const char *name);



#define KNET_TRANSPORT_DEFAULT_RECONNECT_INTERVAL 1000

/**
 * knet_handle_set_transport_reconnect_interval
 *
 * @brief Set the interval between transport attempts to reconnect a failed link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * msecs     - milliseconds
 *
 * @return
 * knet_handle_set_transport_reconnect_interval returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_set_transport_reconnect_interval(knet_handle_t knet_h, uint32_t msecs);

/**
 * knet_handle_get_transport_reconnect_interval
 *
 * @brief Get the interval between transport attempts to reconnect a failed link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * msecs     - milliseconds
 *
 * @return
 * knet_handle_get_transport_reconnect_interval returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_handle_get_transport_reconnect_interval(knet_handle_t knet_h, uint32_t *msecs);

/**
 * knet_link_set_config
 *
 * @brief Configure the link to a host
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * transport - one of the KNET_TRANSPORT_xxx constants
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *             this can be null if we don't know the incoming
 *             IP address/port and the link will remain quiet
 *             till the node on the other end will initiate a
 *             connection
 *
 * flags     - KNET_LINK_FLAG_*
 *
 * @return
 * knet_link_set_config returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 uint8_t transport,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr,
			 uint64_t flags);

/**
 * knet_link_get_config
 *
 * @brief Get the link configutation information
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * transport - see knet_link_set_config(3)
 *
 * src_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dst_addr  - sockaddr_storage that can be either IPv4 or IPv6
 *
 * dynamic   - 0 if dst_addr is static or 1 if dst_addr is dynamic.
 *             In case of 1, dst_addr can be NULL and it will be left
 *             untouched.
 *
 * flags     - KNET_LINK_FLAG_*
 *
 * @return
 * knet_link_get_config returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_get_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 uint8_t *transport,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr,
			 uint8_t *dynamic,
			 uint64_t *flags);

/**
 * knet_link_clear_config
 *
 * @brief Clear link information and disconnect the link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * @return
 * knet_link_clear_config returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_clear_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id);

/*
 * Access lists management for open links
 * see also knet_handle_enable_access_lists(3)
 */

/**
 * check_type_t
 * @brief address type enum for knet access lists
 *
 * CHECK_TYPE_ADDRESS is the equivalent of a single entry / IP address.
 *                    for example: 10.1.9.3
 *                    and the entry is stored in ss1. ss2 can be NULL.
 *
 * CHECK_TYPE_MASK    is used to configure network/netmask.
 *                    for example: 192.168.0.0/24
 *                    the network is stored in ss1 and the netmask in ss2.
 *
 * CHECK_TYPE_RANGE   defines a value / range of ip addresses.
 *                    for example: 172.16.0.1-172.16.0.10
 *                    the start is stored in ss1 and the end in ss2.
 *
 * Please be aware that the above examples refer only to IP based protocols.
 * Other protocols might use ss1 and ss2 in slightly different ways.
 * At the moment knet only supports IP based protocol, though that might change
 * in the future.
 */

typedef enum {
	CHECK_TYPE_ADDRESS,
	CHECK_TYPE_MASK,
	CHECK_TYPE_RANGE
} check_type_t;

/**
 * check_acceptreject_t
 *
 * @brief enum for accept/reject in knet access lists
 *
 * accept or reject incoming packets defined in the access list entry
 */

typedef enum {
	CHECK_ACCEPT,
	CHECK_REJECT
} check_acceptreject_t;

/**
 * knet_link_add_acl
 *
 * @brief Add access list entry to an open link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * ss1 / ss2 / type / acceptreject - see typedef definitions for details
 *
 * IMPORTANT: the order in which access lists are added is critical and it
 *            is left to the user to add them in the right order. knet
 *            will not attempt to logically sort them.
 *
 *            For example:
 *            1 - accept from 10.0.0.0/8
 *            2 - reject from 10.0.0.1/32
 *
 *            is not the same as:
 *
 *            1 - reject from 10.0.0.1/32
 *            2 - accept from 10.0.0.0/8
 *
 *            In the first example, rule number 2 will never match because
 *            packets from 10.0.0.1 will be accepted by rule number 1.
 *
 * @return
 * knet_link_add_acl returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_add_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
		      struct sockaddr_storage *ss1,
		      struct sockaddr_storage *ss2,
		      check_type_t type, check_acceptreject_t acceptreject);

/**
 * knet_link_insert_acl
 *
 * @brief Insert access list entry to an open link at given index
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * index     - insert at position "index" where 0 is the first entry and -1
 *             appends to the current list.
 *
 * ss1 / ss2 / type / acceptreject - see typedef definitions for details
 *
 * @return
 * knet_link_insert_acl returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_insert_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 int index,
			 struct sockaddr_storage *ss1,
			 struct sockaddr_storage *ss2,
			 check_type_t type, check_acceptreject_t acceptreject);

/**
 * knet_link_rm_acl
 *
 * @brief Remove access list entry from an open link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * ss1 / ss2 / type / acceptreject - see typedef definitions for details
 *
 * IMPORTANT: the data passed to this API call must match exactly that passed
 *            to knet_link_add_acl(3).
 *
 * @return
 * knet_link_rm_acl returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_rm_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
		     struct sockaddr_storage *ss1,
		     struct sockaddr_storage *ss2,
		     check_type_t type, check_acceptreject_t acceptreject);

/**
 * knet_link_clear_acl
 *
 * @brief Remove all access list entries from an open link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * @return
 * knet_link_clear_acl returns
 * 0 on success.
 * -1 on error and errno is set.
 */

int knet_link_clear_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id);

/**
 * knet_link_set_enable
 *
 * @brief Enable traffic on a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * @return
 * knet_link_set_enable returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_enable(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 unsigned int enabled);

/**
 * knet_link_get_enable
 *
 * @brief Find out whether a link is enabled or not
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * enabled   - 0 disable the link, 1 enable the link
 *
 * @return
 * knet_link_get_enable returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_enable(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 unsigned int *enabled);



#define KNET_LINK_DEFAULT_PING_INTERVAL  1000 /* 1 second */
#define KNET_LINK_DEFAULT_PING_TIMEOUT   2000 /* 2 seconds */
#define KNET_LINK_DEFAULT_PING_PRECISION 2048 /* samples */

/**
 * knet_link_set_ping_timers
 *
 * @brief Set the ping timers for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * interval  - specify the ping interval in milliseconds.
 *
 * timeout   - if no pong is received within this time,
 *             the link is declared dead, in milliseconds.
 *             NOTE: in future it will be possible to set timeout to 0
 *             for an autocalculated timeout based on interval, pong_count
 *             and latency. The API already accept 0 as value and it will
 *             return ENOSYS / -1. Once the automatic calculation feature
 *             will be implemented, this call will only return EINVAL
 *             for incorrect values.
 *
 * precision - how many values of latency are used to calculate
 *             the average link latency (see also knet_link_get_status(3))
 *
 * @return
 * knet_link_set_ping_timers returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_ping_timers(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			      time_t interval, time_t timeout, unsigned int precision);

/**
 * knet_link_get_ping_timers
 *
 * @brief Get the ping timers for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * interval  - ping interval
 *
 * timeout   - if no pong is received within this time,
 *             the link is declared dead
 *
 * precision - how many values of latency are used to calculate
 *             the average link latency (see also knet_link_get_status(3))
 *
 * @return
 * knet_link_get_ping_timers returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_ping_timers(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			      time_t *interval, time_t *timeout, unsigned int *precision);



#define KNET_LINK_DEFAULT_PONG_COUNT 5

/**
 * knet_link_set_pong_count
 *
 * @brief Set the pong count for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * pong_count - how many valid ping/pongs before a link is marked UP.
 *              default: 5, value should be > 0
 *
 * @return
 * knet_link_set_pong_count returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_pong_count(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			     uint8_t pong_count);

/**
 * knet_link_get_pong_count
 *
 * @brief Get the pong count for a link
 *
 * knet_h     - pointer to knet_handle_t
 *
 * host_id    - see knet_host_add(3)
 *
 * link_id    - see knet_link_set_config(3)
 *
 * pong_count - how many valid ping/pongs before a link is marked UP.
 *              default: 5, value should be > 0
 *
 * @return
 * knet_link_get_pong_count returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_pong_count(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			     uint8_t *pong_count);

/**
 * knet_link_set_priority
 *
 * @brief Set the priority for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * priority  - specify the switching priority for this link
 *             see also knet_host_set_policy
 *
 * @return
 * knet_link_set_priority returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_set_priority(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			   uint8_t priority);

/**
 * knet_link_get_priority
 *
 * @brief Get the priority for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * priority  - gather the switching priority for this link
 *             see also knet_host_set_policy
 *
 * @return
 * knet_link_get_priority returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_priority(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			   uint8_t *priority);

/**
 * knet_link_get_link_list
 *
 * @brief Get a list of links connecting a host
 *
 * knet_h   - pointer to knet_handle_t
 *
 * link_ids - array of at lest KNET_MAX_LINK size
 *            with the list of configured links for a certain host.
 *
 * link_ids_entries -
 *            number of entries contained in link_ids
 *
 * @return
 * knet_link_get_link_list returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_link_list(knet_handle_t knet_h, knet_node_id_t host_id,
			    uint8_t *link_ids, size_t *link_ids_entries);

/*
 * define link status structure for quick lookup
 *
 * src/dst_{ipaddr,port} strings are filled by
 *                       getnameinfo(3) when configuring the link.
 *                       if the link is dynamic (see knet_link_set_config(3))
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
 *
 * knet_link_stats       structure that contains details statistics for the link
 */

#define MAX_LINK_EVENTS 16

struct knet_link_stats {
	/* onwire values */
	uint64_t tx_data_packets;
	uint64_t rx_data_packets;
	uint64_t tx_data_bytes;
	uint64_t rx_data_bytes;
	uint64_t rx_ping_packets;
	uint64_t tx_ping_packets;
	uint64_t rx_ping_bytes;
	uint64_t tx_ping_bytes;
	uint64_t rx_pong_packets;
	uint64_t tx_pong_packets;
	uint64_t rx_pong_bytes;
	uint64_t tx_pong_bytes;
	uint64_t rx_pmtu_packets;
	uint64_t tx_pmtu_packets;
	uint64_t rx_pmtu_bytes;
	uint64_t tx_pmtu_bytes;

	/* Only filled in when requested */
	uint64_t tx_total_packets;
	uint64_t rx_total_packets;
	uint64_t tx_total_bytes;
	uint64_t rx_total_bytes;
	uint64_t tx_total_errors;
	uint64_t tx_total_retries;

	uint32_t tx_pmtu_errors;
	uint32_t tx_pmtu_retries;
	uint32_t tx_ping_errors;
	uint32_t tx_ping_retries;
	uint32_t tx_pong_errors;
	uint32_t tx_pong_retries;
	uint32_t tx_data_errors;
	uint32_t tx_data_retries;

	/* measured in usecs */
	uint32_t latency_min;
	uint32_t latency_max;
	uint32_t latency_ave;
	uint32_t latency_samples;

	/* how many times the link has been going up/down */
	uint32_t down_count;
	uint32_t up_count;

	/*
	 * circular buffer of time_t structs collecting the history
	 * of up/down events on this link.
	 * the index indicates current/last event.
	 * it is safe to walk back the history by decreasing the index
	 */
	time_t   last_up_times[MAX_LINK_EVENTS];
	time_t   last_down_times[MAX_LINK_EVENTS];
	int8_t   last_up_time_index;
	int8_t   last_down_time_index;
	/* Always add new stats at the end */
};

struct knet_link_status {
	size_t size;                    /* For ABI checking */
	char src_ipaddr[KNET_MAX_HOST_LEN];
	char src_port[KNET_MAX_PORT_LEN];
	char dst_ipaddr[KNET_MAX_HOST_LEN];
	char dst_port[KNET_MAX_PORT_LEN];
	uint8_t enabled;	        /* link is configured and admin enabled for traffic */
	uint8_t connected;              /* link is connected for data (local view) */
	uint8_t dynconnected;	        /* link has been activated by remote dynip */
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
	/* Link statistics */
	struct knet_link_stats stats;
};

/**
 * knet_link_get_status
 *
 * @brief Get the status (and statistics) for a link
 *
 * knet_h    - pointer to knet_handle_t
 *
 * host_id   - see knet_host_add(3)
 *
 * link_id   - see knet_link_set_config(3)
 *
 * status    - pointer to knet_link_status struct
 *
 * struct_size - max size of knet_link_status - allows library to
 *               add fields without ABI change. Returned structure
 *               will be truncated to this length and .size member
 *               indicates the full size.
 *
 * @return
 * knet_link_get_status returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_get_status(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 struct knet_link_status *status, size_t struct_size);

/**
 * knet_link_enable_status_change_notify
 *
 * @brief Install a callback to get a link status change events
 *
 * knet_h   - pointer to knet_handle_t
 *
 * host_status_change_notify_fn_private_data -
 *            void pointer to data that can be used to identify
 *            the callback
 *
 * host_status_change_notify_fn -
 *            is a callback function that is invoked every time
 *            there is a change in a link status.
 *            host status is identified by:
 *            - connected, 0 if the link has been disconnected, 1 if the link
 *                         is connected.
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
 * @return
 * knet_host_status_change_notify returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_link_enable_status_change_notify(knet_handle_t knet_h,
					  void *link_status_change_notify_fn_private_data,
					  void (*link_status_change_notify_fn) (
						void *private_data,
						knet_node_id_t host_id,
						uint8_t link_id,
						uint8_t connected,
						uint8_t remote,
						uint8_t external));

/*
 * logging structs/API calls
 */

/*
 * libknet is composed of several subsystems. In order
 * to easily distinguish log messages coming from different
 * places, each subsystem has its own ID.
 *
 *  0-19 config/management
 * 20-39 internal threads
 * 40-59 transports
 * 60-69 crypto implementations
 */

#define KNET_SUB_COMMON         0 /* common.c */
#define KNET_SUB_HANDLE         1 /* handle.c alloc/dealloc config changes */
#define KNET_SUB_HOST           2 /* host add/del/modify */
#define KNET_SUB_LISTENER       3 /* listeners add/del/modify... */
#define KNET_SUB_LINK           4 /* link add/del/modify */
#define KNET_SUB_TRANSPORT      5 /* Transport common */
#define KNET_SUB_CRYPTO         6 /* crypto.c config generic layer */
#define KNET_SUB_COMPRESS       7 /* compress.c config generic layer */

#define KNET_SUB_FILTER        19 /* allocated for users to log from dst_filter */

#define KNET_SUB_DSTCACHE      20 /* switching thread (destination cache handling) */
#define KNET_SUB_HEARTBEAT     21 /* heartbeat thread */
#define KNET_SUB_PMTUD         22 /* Path MTU Discovery thread */
#define KNET_SUB_TX            23 /* send to link thread */
#define KNET_SUB_RX            24 /* recv from link thread */

#define KNET_SUB_TRANSP_BASE   40 /* Base log level for transports */
#define KNET_SUB_TRANSP_LOOPBACK (KNET_SUB_TRANSP_BASE + KNET_TRANSPORT_LOOPBACK)
#define KNET_SUB_TRANSP_UDP      (KNET_SUB_TRANSP_BASE + KNET_TRANSPORT_UDP)
#define KNET_SUB_TRANSP_SCTP     (KNET_SUB_TRANSP_BASE + KNET_TRANSPORT_SCTP)

#define KNET_SUB_NSSCRYPTO     60 /* nsscrypto.c */
#define KNET_SUB_OPENSSLCRYPTO 61 /* opensslcrypto.c */

#define KNET_SUB_ZLIBCOMP      70 /* compress_zlib.c */
#define KNET_SUB_LZ4COMP       71 /* compress_lz4.c */
#define KNET_SUB_LZ4HCCOMP     72 /* compress_lz4.c */
#define KNET_SUB_LZO2COMP      73 /* compress_lzo.c */
#define KNET_SUB_LZMACOMP      74 /* compress_lzma.c */
#define KNET_SUB_BZIP2COMP     75 /* compress_bzip2.c */
#define KNET_SUB_ZSTDCOMP      76 /* compress_zstd.c */

#define KNET_SUB_UNKNOWN       UINT8_MAX - 1
#define KNET_MAX_SUBSYSTEMS    UINT8_MAX

/*
 * Convert between subsystem IDs and names
 */

/**
 * knet_log_get_subsystem_name
 *
 * @brief Get a logging system name from its numeric ID
 *
 * @return
 * returns internal name of the subsystem or "common"
 */

const char *knet_log_get_subsystem_name(uint8_t subsystem);

/**
 * knet_log_get_subsystem_id
 *
 * @brief Get a logging system ID from its name
 *
 * @return
 * returns internal ID of the subsystem or KNET_SUB_COMMON
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

/**
 * knet_log_get_loglevel_name
 *
 * @brief Get a logging level name from its numeric ID
 *
 * @return
 * returns internal name of the log level or "ERROR" for unknown values
 */

const char *knet_log_get_loglevel_name(uint8_t level);

/**
 * knet_log_get_loglevel_id
 *
 * @brief Get a logging level ID from its name
 *
 * @return
 * returns internal log level ID or KNET_LOG_ERR for invalid names
 */

uint8_t knet_log_get_loglevel_id(const char *name);

/*
 * every log message is composed by a text message
 * and message level/subsystem IDs.
 * In order to make debugging easier it is possible to send those packets
 * straight to stdout/stderr (see knet_bench.c stdout option).
 */

#define KNET_MAX_LOG_MSG_SIZE    254
#if KNET_MAX_LOG_MSG_SIZE > PIPE_BUF
#error KNET_MAX_LOG_MSG_SIZE cannot be bigger than PIPE_BUF for guaranteed system atomic writes
#endif

struct knet_log_msg {
	char	msg[KNET_MAX_LOG_MSG_SIZE];
	uint8_t	subsystem;	/* KNET_SUB_* */
	uint8_t msglevel;	/* KNET_LOG_* */
	knet_handle_t knet_h;	/* pointer to the handle generating the log */
};

/**
 * knet_log_set_loglevel
 *
 * @brief Set the logging level for a subsystem
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
 * @return
 * knet_log_set_loglevel returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_log_set_loglevel(knet_handle_t knet_h, uint8_t subsystem,
			  uint8_t level);

/**
 * knet_log_get_loglevel
 *
 * @brief Get the logging level for a subsystem
 *
 * knet_h     - same as above
 *
 * subsystem  - same as above
 *
 * level      - same as above
 *
 * @return
 * knet_log_get_loglevel returns
 * 0 on success
 * -1 on error and errno is set.
 */

int knet_log_get_loglevel(knet_handle_t knet_h, uint8_t subsystem,
			  uint8_t *level);

#endif
