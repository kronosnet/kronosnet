#include "config.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "logging.h"

int init_logging(int debug, int daemonize)
{
	int mode = LOG_MODE_OUTPUT_FILE | LOG_MODE_OUTPUT_SYSLOG;
	int syslog_facility = SYSLOGFACILITY;
	int syslog_priority = SYSLOGLEVEL;
	char logfile[PATH_MAX];
	int logfile_priority = SYSLOGLEVEL;

	memset(logfile, 0, PATH_MAX);
	sprintf(logfile, LOGDIR "/" PACKAGE ".log");

	if (!daemonize)
		mode |= LOG_MODE_OUTPUT_STDERR;

	if (debug)
		logfile_priority = LOG_DEBUG;

	return logt_init(PACKAGE, mode, syslog_facility, syslog_priority,
			 logfile_priority, logfile);
}

void close_logging(void)
{
	logt_exit();
}
