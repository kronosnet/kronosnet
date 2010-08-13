#include "conf.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static int parse_config(FILE *fp, struct peer **head)
{
	

	return 0;
}

int readconf(const char *conffile, struct peer **head)
{
	FILE *fp;
	int res = 0;

	fp = fopen (conffile, "r");
	if (fp == NULL) {
		fprintf(stderr, "Unable to open config file [%s] reason [%s]\n",
			conffile, strerror(errno));
		return -1;
	}

	res = parse_config(fp, head);

	fclose(fp);

	return res;
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
