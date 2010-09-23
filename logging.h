#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <limits.h>
#include <corosync/engine/logsys.h>

#include "conf.h"

struct logging_conf {
	int mode;
	int syslog_priority;
	int syslog_facility;
	int logfile_priority;
	int debug;
	char logfile[PATH_MAX];
};

int configure_logging(confdb_handle_t handle);
void close_logging(void);

#endif
