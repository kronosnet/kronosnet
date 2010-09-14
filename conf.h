#ifndef __CONF_H__
#define __CONF_H__

#include <corosync/corotypes.h>
#include <corosync/confdb.h>

confdb_handle_t readconf(const char *conffile);
void freeconf(confdb_handle_t handle);

int parse_global_config(confdb_handle_t handle);

#endif
