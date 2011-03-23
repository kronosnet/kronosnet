#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

extern int utils_debug;
extern int utils_syslog;

#define log_debug(fmt, args...)	\
do { \
	if (utils_debug) { \
		printf("DEBUG(%s:%i|%s): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##args); \
		if (utils_syslog) syslog(LOG_DEBUG, "DEBUG(%s:%i|%s): " fmt, __FILE__, __LINE__, __FUNCTION__, ##args); \
	} \
} while (0);

#define log_info(fmt, args...) \
do { \
	fprintf(stderr, "Notice: " fmt "\n", ##args); \
	if (utils_syslog) syslog(LOG_INFO, fmt, ##args); \
} while (0);

#define log_error(fmt, args...) \
do { \
	fprintf(stderr, "Error: " fmt " (%s)\n", ##args, strerror(errno)); \
	if (utils_syslog) syslog(LOG_ERR, fmt, ##args); \
} while (0);

#endif
