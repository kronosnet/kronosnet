#include "config.h"

#include "logging.h"

void logging_init_defaults(int debug, int daemonize, const char *logfile)
{
	int level = SYSLOGLEVEL;
	int32_t filetarget;

	if (debug) {
		level = LOG_DEBUG;
	}

	qb_log_init(PACKAGE "d", SYSLOGFACILITY, level);

	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);
	if (debug) {
		qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_PRIORITY_BUMP,
			   LOG_INFO - LOG_DEBUG);
	}

	/*
	 * initialize stderr output only if we are not forking in background
	 */
	if (!daemonize) {
		qb_log_format_set(QB_LOG_STDERR, "%t %N [%p]: %b");
		qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_TRUE);
		qb_log_filter_ctl(QB_LOG_STDERR, QB_LOG_FILTER_ADD,
				  QB_LOG_FILTER_FUNCTION, "", level);
	}

	filetarget = qb_log_file_open(logfile);
	qb_log_ctl(filetarget, QB_LOG_CONF_ENABLED, QB_TRUE);
	qb_log_format_set(filetarget, "%t %N [%p]: %b");
	qb_log_filter_ctl(filetarget, QB_LOG_FILTER_ADD,
			  QB_LOG_FILTER_FUNCTION, "", level);

	qb_log_thread_start();
	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_THREADED, QB_TRUE);
	qb_log_ctl(filetarget, QB_LOG_CONF_THREADED, QB_TRUE);
}

void logging_fini(void)
{
	qb_log_fini();
}
