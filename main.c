#include "config.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"
#include "controlt.h"
#include "netsocket.h"
#include "utils.h"
#include "knet.h"
#include "controlt_comm.h"

#define LOCKFILE_NAME RUNDIR PACKAGE ".pid"

#define OPTION_STRING "hdfVc:"

#define DEFAULT_NET_NAME	"kronosnet%d"

int daemonize = 1;
int debug = 0;
int daemon_quit = 0;
char *conffile = NULL;
int statistics = 0;
int rerouting = 0;
int net_sock;
int eth_fd;
char localnet[16]; /* match IFNAMSIZ from linux/if.h */
static pthread_t eth_thread;
static pthread_t hb_thread;
struct node *mainconf;
uint32_t our_nodeid;

static void print_usage(void)
{
	printf("Usage:\n\n");
	printf(PACKAGE " [options]\n\n");
	printf("Options:\n\n");
	printf("  -c <file> Use config file (default "CONFFILE")\n");
	printf("  -f        Do not fork in background\n");
	printf("  -d        Enable debugging output\n");
	printf("  -h        This help\n");
	printf("  -V        Print program version information\n");
	return;
}

static void read_arguments(int argc, char **argv)
{
	int cont = 1;
	int optchar;

	while (cont) {
		optchar = getopt(argc, argv, OPTION_STRING);

		switch (optchar) {

		case 'c':
			conffile = strdup(optarg);
			break;

		case 'd':
			debug = 1;
			break;

		case 'f':
			daemonize = 0;
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;

		case 'V':
			printf(PACKAGE " " PACKAGE_VERSION " (built " __DATE__
			       " " __TIME__ ")\n");
			exit(EXIT_SUCCESS);
			break;

		case EOF:
			cont = 0;
			break;

		default:
			fprintf(stderr, "unknown option: %c\n", optchar);
			print_usage();
			exit(EXIT_FAILURE);
			break;

		}
	}
}

static void set_oom_adj(int val)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%i", val);
	fclose(fp);
}

static void set_scheduler(void)
{
	struct sched_param sched_param;
	int err;

	err = sched_get_priority_max(SCHED_RR);
	if (err != -1) {
		sched_param.sched_priority = err;
		err = sched_setscheduler(0, SCHED_RR, &sched_param);
		if (err == -1)
			log_printf(LOGSYS_LEVEL_WARNING,
				   "could not set SCHED_RR priority %d err %d",
				   sched_param.sched_priority, errno);
	} else {
		log_printf(LOGSYS_LEVEL_WARNING,
			   "could not get maximum scheduler priority err %d",
			   errno);
	}
}

static void remove_lockfile(void)
{
	unlink(LOCKFILE_NAME);
}

static int create_lockfile(const char *lockfile)
{
	int fd, value;
	size_t bufferlen;
	ssize_t write_out;
	struct flock lock;
	char buffer[50];

	if ((fd = open(lockfile, O_CREAT | O_WRONLY,
		       (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) < 0) {
		fprintf(stderr, "Cannot open lockfile [%s], error was [%s]\n",
			lockfile, strerror(errno));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

retry_fcntl:

	if (fcntl(fd, F_SETLK, &lock) < 0) {
		switch (errno) {
		case EINTR:
			goto retry_fcntl;
			break;
		case EACCES:
		case EAGAIN:
			fprintf(stderr, "Cannot lock lockfile [%s], error was [%s]\n",
				lockfile, strerror(errno));
			break;
		default:
			fprintf(stderr, "process is already running\n");
		}

		goto fail_close;
	}

	if (ftruncate(fd, 0) < 0) {
		fprintf(stderr, "Cannot truncate pidfile [%s], error was [%s]\n",
			lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer)-1, "%u\n", getpid());

	bufferlen = strlen(buffer);
	write_out = write(fd, buffer, bufferlen);

	if ((write_out < 0) || (write_out == 0 && errno)) {
		fprintf(stderr, "Cannot write pid to pidfile [%s], error was [%s]\n",
			lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	if ((write_out == 0) || (write_out < bufferlen)) {
		fprintf(stderr, "Cannot write pid to pidfile [%s], shortwrite of"
				"[%zu] bytes, expected [%zu]\n",
				lockfile, write_out, bufferlen);

		goto fail_close_unlink;
	}

	if ((value = fcntl(fd, F_GETFD, 0)) < 0) {
		fprintf(stderr, "Cannot get close-on-exec flag from pidfile [%s], "
				"error was [%s]\n", lockfile, strerror(errno));

		goto fail_close_unlink;
	}
	value |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, value) < 0) {
		fprintf(stderr, "Cannot set close-on-exec flag from pidfile [%s], "
				"error was [%s]\n", lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	return 0;

fail_close_unlink:
	if (unlink(lockfile))
		fprintf(stderr, "Unable to unlink %s\n", lockfile);

fail_close:
	if (close(fd))
		fprintf(stderr, "Unable to close %s file descriptor\n", lockfile);
	return -1;
}

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigpipe_handler(int sig)
{
	return;
}

static void dispatch_buffer(struct node *next, uint32_t nodeid, char *read_buf, ssize_t read_len)
{
	while (next) {
		struct conn *conn;

		if ((nodeid) && (next->nodeid != nodeid)) {
			log_printf(LOGSYS_LEVEL_INFO, "Requested nodeid: %u current: %u\n", nodeid, next->nodeid);
			goto next;
		}

		conn = next->conn;
		while (conn) {
			if (conn->fd) {
				if (do_write(conn->fd, read_buf, read_len + sizeof(struct knet_header)) < 0) {
						log_printf(LOGSYS_LEVEL_INFO, "Unable to dispatch buf: %s\n", strerror(errno));
				}
			}
			conn = conn->next;
		}
next:
		next = next->next;
	}
}

static void *heartbeat_thread(void *arg)
{
	struct knet_header knet_h;

	memset(&knet_h, 0, sizeof(struct knet_header));
	knet_h.magic = KNETD_MAGIC;
	knet_h.src_nodeid = our_nodeid;
	knet_h.seq_num = 0;
	knet_h.pckt_type = KNETD_PKCT_TYPE_PING;
	knet_h.compress = KNETD_COMPRESS_OFF;
	knet_h.encryption = KNETD_ENCRYPTION_OFF;

	for (;;) {
		sleep(100);
		knet_h.seq_num++;
		//dispatch_buffer(mainconf, 1, (char *)&knet_h, sizeof(struct knet_header));
	}
	return NULL;
}

static void *eth_to_knet_thread(void *arg)
{
	fd_set rfds;
	int se_result;
	char read_buf[131072+sizeof(struct knet_header)];
	ssize_t read_len = 0;
	struct timeval tv;
	struct knet_header *knet_h = (struct knet_header *)read_buf;

	/* we need to prepare the header only once for now */
	memset(knet_h, 0, sizeof(struct knet_header));
	knet_h->magic = KNETD_MAGIC;
	knet_h->src_nodeid = our_nodeid;
	knet_h->seq_num = 0;
	knet_h->pckt_type = KNETD_PKCT_TYPE_DATA;
	knet_h->compress = KNETD_COMPRESS_OFF;
	knet_h->encryption = KNETD_ENCRYPTION_OFF;

	do {
		FD_ZERO (&rfds);
		FD_SET (eth_fd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((eth_fd + 1), &rfds, 0, 0, &tv);
		if (se_result == -1) {
			log_printf(LOGSYS_LEVEL_CRIT, "Unable to select in eth thread: %s\n", strerror(errno));
			daemon_quit = 1;
		}

		if (se_result == 0)
			continue;

		if (FD_ISSET(eth_fd, &rfds)) {
			read_len = read(eth_fd, read_buf + sizeof(struct knet_header), sizeof(read_buf) - sizeof(struct knet_header));
			if (read_len > 0) {
				knet_h->seq_num++;
				dispatch_buffer(mainconf, 0, read_buf, read_len + sizeof(struct knet_header));
			} else if (read_len < 0) {
				log_printf(LOGSYS_LEVEL_INFO, "Error reading from localnet error: %s\n", strerror(errno));
			} else
				log_printf(LOGSYS_LEVEL_DEBUG, "Read 0?\n");
		}
	} while (se_result >= 0 && !daemon_quit);

	return NULL;
}

static void loop(void) {
	int se_result;
	fd_set rfds;
	struct timeval tv;
	char read_buf[131072 + sizeof(struct knet_header)];
	ssize_t read_len = 0;
	int rv;
	uint32_t peer_nodeid;
	struct knet_header *knet_h = (struct knet_header *)read_buf;
	struct node *peer;

	do {
		FD_ZERO (&rfds);
		FD_SET (net_sock, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((net_sock + 1), &rfds, 0, 0, &tv);

		if (daemon_quit)
			goto out;

		if (se_result == -1) {
			log_printf(LOGSYS_LEVEL_CRIT, "Unable to select: %s\n", strerror(errno));
			goto out;
		}

		if (se_result == 0)
			continue;

		if (FD_ISSET(net_sock, &rfds)) {
			read_len = read(net_sock, read_buf, sizeof(read_buf));
			if (read_len > 0) {
				//log_printf(LOGSYS_LEVEL_DEBUG, "Magic: %u\nnodeid: %u\nseq_num: %u\npckt_type: %i\ncompress: %i\nencryption: %i\npadding: %i\n", knet_h->magic, knet_h->nodeid, knet_h->seq_num, knet_h->pckt_type, knet_h->compress, knet_h->encryption, knet_h->padding);

				if (knet_h->magic != KNETD_MAGIC) {
					log_printf(LOGSYS_LEVEL_DEBUG, "no magic? print peer info for fun and profit\n");
					continue;
				}

				if (knet_h->src_nodeid == our_nodeid) {
					log_printf(LOGSYS_LEVEL_DEBUG, "Are we really sending pckts to our selves?\n");
					continue;
				}

				/* optimize this to do faster lookups */
				peer = mainconf;
				while (peer) {
					if (peer->nodeid == knet_h->src_nodeid)
						break;
					peer = peer->next;
				}
				switch(knet_h->pckt_type) {
					case KNETD_PKCT_TYPE_DATA:
						if (should_deliver(peer, knet_h->seq_num) > 0) {
							//log_printf(LOGSYS_LEVEL_DEBUG, "Act pkct from node %s[%u]: %u\n", peer->nodename, peer->nodeid, knet_h->seq_num);
							rv = do_write(eth_fd, read_buf + sizeof(struct knet_header), read_len - sizeof(struct knet_header));
							if (rv < 0)
								log_printf(LOGSYS_LEVEL_INFO, "Error writing to eth_fd: %s\n", strerror(errno));
							else
								has_been_delivered(peer, knet_h->seq_num);
						} //else
						//	log_printf(LOGSYS_LEVEL_DEBUG, "Discarding duplicated package from node %s[%u]: %u\n", peer->nodename, peer->nodeid, knet_h->seq_num);
						break;
					case KNETD_PKCT_TYPE_PING:
						log_printf(LOGSYS_LEVEL_DEBUG, "Got a PING request %u\n", knet_h->src_nodeid);
						peer_nodeid = knet_h->src_nodeid;

						/* reply */
						knet_h->pckt_type = KNETD_PKCT_TYPE_PONG;
						knet_h->src_nodeid = our_nodeid;
						dispatch_buffer(mainconf, peer_nodeid, read_buf, read_len);
						break;
					case KNETD_PKCT_TYPE_PONG:
						log_printf(LOGSYS_LEVEL_DEBUG, "Got a PONG reply\n");
						/* need to correlate this with a PING */
						break;
					default:
						log_printf(LOGSYS_LEVEL_INFO, "Error: received unknown packet type on network socket\n");
						break;
				}
			} else if (read_len < 0) {
				log_printf(LOGSYS_LEVEL_INFO, "Error reading from KNET error %d: %s\n", net_sock, strerror(errno));
			} else
				log_printf(LOGSYS_LEVEL_DEBUG, "Read 0?\n");
		} 
out:
		if (se_result <0 || daemon_quit)
			log_printf(LOGSYS_LEVEL_DEBUG, "End of mail loop\n");
	} while (se_result >= 0 && !daemon_quit);
}

int main(int argc, char **argv)
{
	confdb_handle_t confdb_handle = 0;
	int rv;
	int eth_thread_started = 1, hb_thread_started = 1;

	if (create_lockfile(LOCKFILE_NAME) < 0)
		exit(EXIT_FAILURE);

	atexit(remove_lockfile);

	read_arguments(argc, argv);

	strncpy(localnet, DEFAULT_NET_NAME, sizeof(DEFAULT_NET_NAME));

	if (!conffile)
		conffile = strdup(CONFFILE);

	confdb_handle = readconf(conffile);
	if (confdb_handle == 0)
		exit(EXIT_FAILURE);

	if (configure_logging(confdb_handle) < 0) {
		fprintf(stderr, "Unable to initialize logging subsystem\n");
		exit(EXIT_FAILURE);
	}
	log_printf(LOGSYS_LEVEL_INFO, PACKAGE " version " VERSION "\n");

	if (daemonize) {
		if (daemon(0, 0) < 0) {
			perror("Unable to daemonize");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGTERM, sigterm_handler);
	signal(SIGPIPE, sigpipe_handler);

	parse_global_config(confdb_handle);
	mainconf = parse_nodes_config(confdb_handle);

	if (process_local_node_config_preup(mainconf, localnet) != 0) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to process local node config\n");
		goto out;
	}

	if (statistics)
		log_printf(LOGSYS_LEVEL_DEBUG, "statistics collector enabled\n");
	if (rerouting)
		log_printf(LOGSYS_LEVEL_DEBUG, "rerouting engine enabled\n");

	log_printf(LOGSYS_LEVEL_DEBUG, "Adjust OOM to -16\n");
	set_oom_adj(-16);

	log_printf(LOGSYS_LEVEL_DEBUG, "Set RR scheduler\n");
	set_scheduler();

	/* do stuff here, should we */
	log_printf(LOGSYS_LEVEL_DEBUG, "Starting daemon control thread\n");
	if (start_control_thread() < 0)
		goto out;

	log_printf(LOGSYS_LEVEL_DEBUG, "Initializing local ethernet\n");
	eth_fd = knet_open(localnet, 16);
	if (eth_fd < 0) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to inizialize local tap device: %s\n",
			   strerror(errno));
		goto out;
	}
	log_printf(LOGSYS_LEVEL_INFO, "Using local net device %s\n", localnet);

	if (process_local_node_config_postup(mainconf, localnet) != 0) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to process post up config\n");
		goto out;
	}

	log_printf(LOGSYS_LEVEL_DEBUG, "Initializing local ethernet delivery thread\n");

	rv = pthread_create(&eth_thread, NULL, eth_to_knet_thread, NULL);
	if (rv < 0) {
		eth_thread_started = 0;
		log_printf(LOGSYS_LEVEL_INFO, "Unable to inizialize local RX thread. error: %s\n",
			   strerror(errno));
		goto out;
	}

	log_printf(LOGSYS_LEVEL_DEBUG, "Opening sockets to other nodes\n");
	connect_to_nodes(mainconf);

	log_printf(LOGSYS_LEVEL_DEBUG, "Here we need to configure the ethernet ip/pre/post/stuff\n");

	log_printf(LOGSYS_LEVEL_DEBUG, "Starting network socket listener\n");
	net_sock = setup_net_listener();
	if (net_sock < 0)
		goto out;

	log_printf(LOGSYS_LEVEL_DEBUG, "Starting heartbeat thread\n");
	rv = pthread_create(&hb_thread, NULL, heartbeat_thread, NULL);
	if (rv < 0) {
		hb_thread_started = 0;
		log_printf(LOGSYS_LEVEL_INFO, "Unable to inizialize heartbeat thread. error: %s\n",
			   strerror(errno));
		goto out;
	}

	log_printf(LOGSYS_LEVEL_DEBUG, "Entering main loop\n");
	loop();

out:
	if (hb_thread_started > 0)
		pthread_cancel(hb_thread);

	if (eth_thread_started > 0)
		pthread_cancel(eth_thread);

	disconnect_from_nodes(mainconf);

	if (eth_fd >= 0)
		close(eth_fd);

	if (net_sock >= 0)
		close(net_sock);

	stop_control_thread();

	free_nodes_config(mainconf);

	free(conffile);

	freeconf(confdb_handle);

	close_logging();

	return 0;
}
