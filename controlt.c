#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "controlt.h"
#include "controlt_comm.h"
#include "logging.h"
#include "utils.h"

static pthread_t ctrl_thread;
static pthread_mutex_t ctrl_mutex;
int control_thread_active = 0;

static int setup_listener(void)
{
	struct sockaddr_un addr;
	int rv, s, value;

	unlink(CLUSTERNETD_SOCKNAME);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		logt_print(LOG_INFO, "Unable to open socket %s error: %s\n",
				     CLUSTERNETD_SOCKNAME, strerror(errno));
		return s;
	}

	value = fcntl(s, F_GETFD, 0);
	if (value < 0) {
		logt_print(LOG_INFO, "Unable to get close-on-exec flag from socket %s error: %s\n",
				     CLUSTERNETD_SOCKNAME, strerror(errno));
		close(s);
		return value;
	}
	value |= FD_CLOEXEC;
	rv = fcntl(s, F_SETFD, value);
	if (rv < 0) {
		logt_print(LOG_INFO, "Unable to set close-on-exec flag from socket %s error: %s\n",
					CLUSTERNETD_SOCKNAME, strerror(errno));
		close(s);
		return rv;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, CLUSTERNETD_SOCKNAME, strlen(CLUSTERNETD_SOCKNAME));

	rv = bind(s, (struct sockaddr *) &addr, sizeof(addr));
	if (rv < 0) {
		logt_print(LOG_INFO, "Unable to bind to socket %s error: %s\n",
				     CLUSTERNETD_SOCKNAME, strerror(errno));
		close(s);
		return rv;
	}

	rv = listen(s, SOMAXCONN);
	if (rv < 0) {
		logt_print(LOG_INFO, "Unable to listen to socket %s error: %s\n",
				     CLUSTERNETD_SOCKNAME, strerror(errno));
		close(s);
		return rv;
	}

	return s;
}

static void ctrl_lock(void)
{
	pthread_mutex_lock(&ctrl_mutex);
}

static void ctrl_unlock(void)
{
	pthread_mutex_unlock(&ctrl_mutex);
}

static void *control_thread(void *arg)
{
	int ctrl_socket, ctrl_fd, rv;
	struct ctrl_header h;

	ctrl_socket = setup_listener();
	if (ctrl_socket < 0) {
		control_thread_active = -1;
		goto thread_out;
	}

	control_thread_active = 1;

	for (;;) {
		logt_print(LOG_DEBUG, "Waiting for connections on ctrl socket\n");
		ctrl_fd = accept(ctrl_socket, NULL, NULL);
		if (ctrl_fd < 0) {
			logt_print(LOG_INFO, "Error accepting connections on socket %s error: %s\n",
				   CLUSTERNETD_SOCKNAME, strerror(errno));
			// what now? doesn't look ok to kill the control thread.. try again?
			goto thread_out;
		}

		rv = do_read(ctrl_fd, &h, sizeof(h));
		if (rv < 0)
			goto out;

		if (h.magic != CNETD_MAGIC)
			goto out;

		if ((h.version & 0xFFFF0000) != (CNETD_VERSION & 0xFFFF0000))
			goto out;

		ctrl_lock();

		switch(h.command) {
		case CNETD_CMD_QUIT:
			logt_print(LOG_DEBUG, "Received CNETD_CMD_QUIT on control socket\n");
			break;
		default:
			logt_print(LOG_DEBUG, "Unknown command received on control socket\n");
			break;
		}

		ctrl_unlock();

out:
		close(ctrl_fd);
	}

thread_out:
	unlink(CLUSTERNETD_SOCKNAME);
	return NULL;
}

int start_control_thread(void)
{
	int rv;

	if (pthread_mutex_init(&ctrl_mutex, NULL) < 0)
		logt_print(LOG_INFO, "Unable to initialize control mutex: %s\n", strerror(errno));

	rv = pthread_create(&ctrl_thread, NULL, control_thread, NULL);
	if (rv < 0)
		logt_print(LOG_INFO, "Unable to create control thread: %s\n", strerror(errno));

	while (control_thread_active == 0)
		sleep(1);

	if (control_thread_active < 0)
		rv = control_thread_active;

	return rv;
}

int stop_control_thread(void)
{
	int rv;

	rv = pthread_cancel(ctrl_thread);
	unlink(CLUSTERNETD_SOCKNAME);

	return rv;
}
