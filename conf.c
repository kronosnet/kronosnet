#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "conf.h"

static int parse_config(FILE *fp, struct peer **head)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	struct peer *new = NULL;
	struct peer *tmp = NULL;

	while ((read = getline(&line, &len, fp)) != -1) {
		/* clear newline */
		if ((read) && (line[read - 1] == '\n')) {
			line[read - 1] = '\0';
			read--;
		}
		if ((read) && (line[read - 1] == '\r')) {
			line[read - 1] = '\0';
			read--;
		}

		if ((!read) || ((read) && (line[0] == '#')))
			continue;

		new = malloc(sizeof(struct peer));
		if (!new) {
			fprintf(stderr, "Unable to allocate memory for peer list!!\n");
			return -1;
		}

		new->line=strdup(line);
		if(new->line == NULL) {
			fprintf(stderr, "Unable to allocate memory for peer line entry\n");
			return -1;
		}

		if (tmp == NULL)
			tmp = new;
		else
			tmp->tail->next = new;

		tmp->tail = new;
	}

	if (line)
		free(line);

	*head = tmp;

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
