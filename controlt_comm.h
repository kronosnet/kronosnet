#ifndef __CONTROLT_COMM_H__
#define __CONTROLT_COMM_H__

struct ctrl_header {
	unsigned int magic;
	unsigned int version;
	unsigned int command;
	unsigned int option;
	unsigned int len;
	int data;		/* embedded command-specific data, for convenience */
	int unused1;
	int unsued2;
};

#endif
