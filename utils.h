#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <syslog.h>

extern int utils_debug;

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
	syslog(LOG_INFO, fmt, ##args); \
} while (0);

#define log_error(fmt, args...) \
do { \
	fprintf(stderr, "Error: " fmt "\n", ##args); \
	syslog(LOG_ERR, fmt, ##args); \
} while (0);

#endif
