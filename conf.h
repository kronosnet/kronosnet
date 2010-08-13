#ifndef __CONF_H__
#define __CONF_H__

struct peer {
	struct peer *next;
	struct peer *tail;
	const char *line;
};

int readconf(const char *conffile, struct peer **head);
void freeconf(struct peer *head);

#endif
