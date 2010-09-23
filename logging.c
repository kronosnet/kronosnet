#include "config.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "conf.h"
#define SYSLOG_NAMES
#include <syslog.h>
#include "logging.h"

#define SUBSYSNAME PACKAGE

LOGSYS_DECLARE_SYSTEM (PACKAGE,	/* name */
	LOGSYS_MODE_OUTPUT_STDERR | LOGSYS_MODE_THREADED | LOGSYS_MODE_FORK, /* mode */
	0,			/* debug */
	NULL,			/* logfile path */
	LOGSYS_LEVEL_INFO,	/* logfile_priority */
	LOG_DAEMON,		/* syslog facility */
	LOGSYS_LEVEL_INFO,	/* syslog level */
	NULL,			/* use default format */
	1000000);		/* flight recorder size */

static struct logging_conf *conf = NULL;
extern int debug;
extern int daemonize;

static int facility_id_get(char *name)
{
	unsigned int i;
	for (i = 0; facilitynames[i].c_name != NULL; i++) {
		if (strcasecmp(name, facilitynames[i].c_name) == 0) {
			return (facilitynames[i].c_val);
		}
	}
	return (-1);
}

static int priority_id_get(char *name)
{
	unsigned int i;
	for (i = 0; prioritynames[i].c_name != NULL; i++) {
		if (strcasecmp(name, prioritynames[i].c_name) == 0) {
			return (prioritynames[i].c_val);
		}
	}
	return (-1);
}

static int parse_logging_config(confdb_handle_t handle)
{
	int res;
	hdb_handle_t logging_handle;
	char key_name[PATH_MAX];
	size_t key_name_len;
	char key_value[PATH_MAX];
	size_t key_value_len;

	conf->mode = LOGSYS_MODE_OUTPUT_FILE | LOGSYS_MODE_OUTPUT_SYSLOG;
	conf->syslog_priority = SYSLOGLEVEL;
	conf->syslog_facility = SYSLOGFACILITY;
	conf->logfile_priority = SYSLOGLEVEL;
	conf->debug = 0;

	memset(conf->logfile, 0, PATH_MAX);
	sprintf(conf->logfile, LOGDIR "/" PACKAGE ".log");

	res = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK)
		return -1;

	res = confdb_object_find(handle, OBJECT_PARENT_HANDLE, "logging", strlen("logging"), &logging_handle);

	confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK)
		return 0;

	res = confdb_key_iter_start(handle, logging_handle);
	if (res != CS_OK)
		return -1;

	while ( (res = confdb_key_iter(handle, logging_handle, key_name, &key_name_len,
					key_value, &key_value_len)) == CS_OK) {
		int val;

		key_name[key_name_len] = '\0';
		key_value[key_value_len] = '\0';

		if (!strncmp(key_name, "debug", strlen("debug"))) {
			if (!debug) {
				if (!strncmp(key_value, "on", 2))
					debug=1;
				if (!strncmp(key_value, "off", 3))
					debug=0;
			}
		} else if (!strncmp(key_name, "to_logfile", strlen("to_logfile"))) {
			if (!strncmp(key_value, "yes", 3))
				conf->mode |= LOGSYS_MODE_OUTPUT_FILE;
			if (!strncmp(key_value, "no", 2))
				conf->mode &= ~LOGSYS_MODE_OUTPUT_FILE;
		} else if (!strncmp(key_name, "to_syslog", strlen("to_syslog"))) {
			if (!strncmp(key_value, "yes", 3))
				conf->mode |= LOGSYS_MODE_OUTPUT_SYSLOG;
			if (!strncmp(key_value, "no", 2))
				conf->mode &= ~LOGSYS_MODE_OUTPUT_SYSLOG;
		} else if (!strncmp(key_name, "syslog_facility", strlen("syslog_facility"))) {
			val = facility_id_get(key_value);
			if (val >= 0)
				conf->syslog_facility = val;
		} else if (!strncmp(key_name, "syslog_priority", strlen("syslog_priority"))) {
			val = priority_id_get(key_value);
			if (val >= 0)
				conf->syslog_priority = val;
		} else if (!strncmp(key_name, "logfile_priority", strlen("logfile_priority"))) {
			val = priority_id_get(key_value);
			if (val >= 0)
				conf->logfile_priority = val;
		} else if (!strncmp(key_name, "logfile", strlen("logfile"))) {
			if (strlen(key_value))
				snprintf(conf->logfile, PATH_MAX, "%s", key_value);
		}
	}

	if (debug)
		conf->debug = 1;

	if (conf->debug)
		conf->logfile_priority = LOGSYS_LEVEL_DEBUG;

	if (!daemonize)
		conf->mode |= LOGSYS_MODE_OUTPUT_STDERR;

	return 0;
}

int configure_logging(confdb_handle_t handle)
{
	if (conf == NULL) {
		conf = malloc(sizeof(struct logging_conf));
		if (!conf) {
			fprintf(stderr, "Unable to allocate memory for logging config defaults\n");
			return -1;
		}
	}

	if (parse_logging_config(handle)) {
		fprintf(stderr, "Unable to parse logging configuration\n");
		return -1;
	}

	if (logsys_config_mode_set(SUBSYSNAME, conf->mode) < 0) {
		fprintf(stderr, "Unable to set logging mode to %i", conf->mode);
		return -1;
	}

	if (logsys_config_debug_set(SUBSYSNAME, conf->debug) < 0) {
		fprintf(stderr, "Unable to set logging debug flag to %i", conf->debug);
		return -1;
	}

	if (logsys_config_file_set(SUBSYSNAME, NULL, conf->logfile) < 0) {
		fprintf(stderr, "Unable to set log file to %s", conf->logfile);
		return -1;
	}

	if (logsys_config_logfile_priority_set(SUBSYSNAME, conf->logfile_priority) < 0) {
		fprintf(stderr, "Unable to set logfile priority to %i", conf->logfile_priority);
		return -1;
	}

	if (logsys_config_syslog_facility_set(SUBSYSNAME, conf->syslog_facility) < 0) {
		fprintf(stderr, "Unable to set syslog facility to %i", conf->syslog_facility);
		return -1;
	}

	if (logsys_config_syslog_priority_set(SUBSYSNAME, conf->syslog_priority) < 0) {
		fprintf(stderr, "Unable to set syslog priority to %i", conf->syslog_priority);
		return -1;
	}

	return 0;
}

void close_logging(void)
{
	if (conf)
		free(conf);

	conf = NULL;

	logsys_atexit();
}
