#include "config.h"

#include <unistd.h>
#include <pthread.h>

#include "controlt.h"
#include "logging.h"

static pthread_t ctrl_thread;
static pthread_mutex_t ctrl_mutex;
int control_thread_active = 0;

static void *control_thread(void *arg)
{
	control_thread_active = 1;

	for (;;) {
		sleep(1);
		logt_print(LOG_DEBUG, "I AM A THREAD!\n");
	}

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
	return pthread_cancel(ctrl_thread);
}
