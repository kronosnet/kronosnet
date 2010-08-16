#include "config.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "conf.h"
#define SYSLOG_NAMES
#include <syslog.h>
#include "logging.h"

struct logging_conf *conf = NULL;
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

	conf->mode = LOG_MODE_OUTPUT_FILE | LOG_MODE_OUTPUT_SYSLOG;
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
			if (!strncmp(key_value, "on", 2))
				debug=1;
			if (!strncmp(key_value, "off", 3))
				debug=0;
		} else if (!strncmp(key_name, "to_logfile", strlen("to_logfile"))) {
			if (!strncmp(key_value, "yes", 3))
				conf->mode |= LOG_MODE_OUTPUT_FILE;
			if (!strncmp(key_value, "no", 2))
				conf->mode &= ~LOG_MODE_OUTPUT_FILE;
		} else if (!strncmp(key_name, "to_syslog", strlen("to_syslog"))) {
			if (!strncmp(key_value, "yes", 3))
				conf->mode |= LOG_MODE_OUTPUT_SYSLOG;
			if (!strncmp(key_value, "no", 2))
				conf->mode &= ~LOG_MODE_OUTPUT_SYSLOG;
		} else if (!strncmp(key_name, "syslog_facility", strlen("syslog_facility"))) {
			val = facility_id_get(key_value);
			if (val >= 0)
				conf->syslog_facility = val;
		} else if (!strncmp(key_name, "syslog_priority", strlen("syslog_priority"))) {
			val = priority_id_get(key_value);
			if (val >= 0)
				conf->syslog_priority = val;
		} else if (!strncmp(key_name, "logfile", strlen("logfile"))) {
			if (strlen(key_value))
				snprintf(conf->logfile, PATH_MAX, "%s", key_value);
		} else if (!strncmp(key_name, "logfile_priority", strlen("logfile_priority"))) {
			val = priority_id_get(key_value);
			if (val >= 0)
				conf->logfile_priority = val;
		}
	}

	if (debug)
		conf->debug = 1;

	if (conf->debug)
		conf->logfile_priority = LOG_DEBUG;

	if (!daemonize)
		conf->mode |= LOG_MODE_OUTPUT_STDERR;

	return 0;
}

int configure_logging(confdb_handle_t handle, int reconf)
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

	if (!reconf)
		return logt_init(PACKAGE, conf->mode, conf->syslog_facility, conf->syslog_priority,
				 conf->logfile_priority, conf->logfile);

	logt_conf(PACKAGE, conf->mode, conf->syslog_facility, conf->syslog_priority,
				 conf->logfile_priority, conf->logfile);

	return 0;
}

void close_logging(void)
{
	logt_exit();
}
