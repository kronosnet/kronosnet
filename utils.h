#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

extern int utils_debug;
extern int utils_syslog;

#ifndef TEST
#define STATIC static
#else
#define STATIC
#endif

#define log_debug(fmt, args...)	\
if (utils_debug) { \
	printf("DEBUG(%s:%i|%s): " fmt "\n", \
			__FILE__, __LINE__, __FUNCTION__, ##args); \
}

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

#define knet_ts_diff(start, end, diff) \
do { \
	if ((end)->tv_sec > (start)->tv_sec) \
		*(diff) = (((end)->tv_sec - (start)->tv_sec) * 1000000) \
			+ (((end)->tv_nsec - (start)->tv_nsec) / 1000); \
	else \
		*(diff) = ((end)->tv_nsec - (start)->tv_nsec) / 1000; \
} while (0);

int knet_fdset_cloexec(int fd);

#endif
