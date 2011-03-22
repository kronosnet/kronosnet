#include "config.h"

#include <stdarg.h>
#include <arpa/telnet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "utils.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

static int check_vty(struct knet_vty *vty)
{
	if (!vty) {
		errno = EINVAL;
		return -1;
	}
	if (vty->got_epipe) {
		errno = EPIPE;
		return -1;
	}
	return 0;
}

/*
 * TODO: implement loopy_write here
 * should sock be non-blocking?
 */
static int knet_vty_loopy_write(struct knet_vty *vty, const char *buf, size_t bufsize)
{
	ssize_t writelen;

	writelen = write(vty->vty_sock, buf, bufsize);
	if (writelen < 0)
		vty->got_epipe = 1;

	return writelen;
}

int knet_vty_write(struct knet_vty *vty, const char *format, ...)
{
	va_list args;
	int len = 0;
	char buf[VTY_MAX_BUFFER_SIZE];

	if (check_vty(vty))
		return -1;

	va_start (args, format);
	len = vsnprintf (buf, VTY_MAX_BUFFER_SIZE, format, args);
	va_end (args);

	if ((len < 0) || (len > VTY_MAX_BUFFER_SIZE))
		return -1;

	return knet_vty_loopy_write(vty, buf, len);
}

static int knet_vty_read_real(struct knet_vty *vty, unsigned char *buf, size_t bufsize,
			      int ignore_iac)
{
	ssize_t readlen;

iac_retry:
	readlen = recv(vty->vty_sock, buf, bufsize, 0);
	if (readlen == 0) {
		vty->got_epipe = 1;
		goto out_clean;
	}
	if (readlen < 0)
		goto out_clean;

	vty->idle = 0;

	/* at somepoint we have to add IAC parsing */
	if ((buf[0] == IAC) && (ignore_iac))
		goto iac_retry;

out_clean:
	return readlen;
}

int knet_vty_read(struct knet_vty *vty, unsigned char *buf, size_t bufsize)
{
	if (check_vty(vty))
		return -1;

	if ((!buf) || (bufsize == 0)) {
		errno = EINVAL;
		return -1;
	}
	return knet_vty_read_real(vty, buf, bufsize, 1);
}

static int knet_vty_set_echooff(struct knet_vty *vty)
{
	unsigned char cmdreply[VTY_MAX_BUFFER_SIZE];
	unsigned char cmdechooff[] = { IAC, WILL, TELOPT_ECHO, '\0' };
	unsigned char cmdechooffreply[] = { IAC, DO, TELOPT_ECHO, '\0' };
	ssize_t readlen;

	if (knet_vty_write(vty, "%s", cmdechooff) < 0)
		return -1;

	readlen = knet_vty_read_real(vty, cmdreply, VTY_MAX_BUFFER_SIZE, 0);
	if (readlen < 0)
		return readlen;

	if (memcmp(&cmdreply, &cmdechooffreply, readlen))
		return -1;

	return 0;
}

static int knet_vty_set_echoon(struct knet_vty *vty)
{
	unsigned char cmdreply[VTY_MAX_BUFFER_SIZE];
	unsigned char cmdechoon[] = { IAC, WONT, TELOPT_ECHO, '\0' };
	unsigned char cmdechoonreply[] = { IAC, DONT, TELOPT_ECHO, '\0' };
	ssize_t readlen;

	if (knet_vty_write(vty, "%s", cmdechoon) < 0)
		return -1;

	readlen = knet_vty_read_real(vty, cmdreply, VTY_MAX_BUFFER_SIZE, 0);
	if (readlen < 0)
		return readlen;

	if (memcmp(&cmdreply, &cmdechoonreply, readlen))
		return -1;

	return 0;
}

int knet_vty_set_echo(struct knet_vty *vty, int on)
{
	if (check_vty(vty))
		return -1;

	if (on)
		return knet_vty_set_echoon(vty);

	return knet_vty_set_echooff(vty);
}

void knet_vty_print_banner(struct knet_vty *vty)
{
	if (check_vty(vty))
		return;

	knet_vty_write(vty,
		"Welcome to " PACKAGE " " PACKAGE_VERSION " (built " __DATE__
		" " __TIME__ ")\n");
}

int knet_vty_set_iacs(struct knet_vty *vty)
{
	unsigned char cmdreply[VTY_MAX_BUFFER_SIZE];
	unsigned char cmdsga[] = { IAC, WILL, TELOPT_SGA, '\0' };
	unsigned char cmdsgareply[] = { IAC, DO, TELOPT_SGA, '\0' };
	unsigned char cmdlm[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
	ssize_t readlen;

	if (check_vty(vty))
		return -1;

	if (knet_vty_set_echo(vty, 0) < 0)
		return -1;

	if (knet_vty_write(vty, "%s", cmdsga) < 0)
		return -1;

	readlen = knet_vty_read_real(vty, cmdreply, VTY_MAX_BUFFER_SIZE, 0);
	if (readlen < 0)
		return readlen;

	if (memcmp(&cmdreply, &cmdsgareply, readlen))
		return -1;

	if (knet_vty_write(vty, "%s", cmdlm) < 0)
		return -1;

	return 0;
}

void knet_vty_free_history(struct knet_vty *vty)
{
	int i;

	if (check_vty(vty))
		return;

	for (i = 0; i < KNET_VTY_MAX_HIST; i++) {
		if (vty->history[i]) {
			free(vty->history[i]);
			vty->history[i] = NULL;
		}
	}
}

void knet_vty_exit_node(struct knet_vty *vty)
{
	switch(vty->node) {
		case NODE_LINK:
			vty->node = NODE_PEER;
			break;
		case NODE_PEER:
			vty->node = NODE_INTERFACE;
			break;
		case NODE_INTERFACE:
			vty->node = NODE_CONFIG;
			break;
		case NODE_CONFIG:
			pthread_mutex_lock(&knet_vty_mutex);
			knet_vty_config = -1;
			pthread_mutex_unlock(&knet_vty_mutex);
			vty->node = NODE_ROOT;
			break;
		case NODE_ROOT:
			vty->got_epipe = 1;
			break;
		default:
			knet_vty_write(vty, "No idea where to go..%s", telnet_newline);
			break;
	}
}

int knet_vty_is_line_empty(struct knet_vty *vty)
{
	int idx;

	for (idx = 0; idx < vty->line_idx; idx++) {
		if (vty->line[idx] != ' ')
			return 0;
	}

	return 1;
}

void knet_vty_prompt(struct knet_vty *vty)
{
	char buf[3];

	if (vty->user_can_enable) {
		buf[0] = '#';
	} else {
		buf[0] = '>';
	}
	buf[1] = ' ';
	buf[2] = 0;
	knet_vty_write(vty, "%s%s", knet_vty_nodes[vty->node].prompt, buf);
}
