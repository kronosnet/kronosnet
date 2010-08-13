#include "conf.h"

#include <stdlib.h>

int readconf(char *conffile, struct peer **head)
{
	return 0;
}

void freeconf(struct peer *head)
{
	struct peer *next;

	while(head) {
		next = head->next;
		free(head);
		head = next;
	}

	return;
}
