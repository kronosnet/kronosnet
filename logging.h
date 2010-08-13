#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <liblogthread.h>

int init_logging(int debug, int daemonize);
void close_logging(void);

#endif
