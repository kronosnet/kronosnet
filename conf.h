#ifndef __CONF_H__
#define __CONF_H__

struct peer {
	struct peer *next;
	struct peer *tail;
};

int readconf(char *conffile, struct peer **head);
void freeconf(struct peer *head);

#endif
