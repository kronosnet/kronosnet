#include "config.h"

#include <stdarg.h>
#include <arpa/telnet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "vty_utils.h"

/*
 * TODO: implement loopy_write here
 * should sock be non-blocking?
 */
static int knet_vty_loopy_write(struct knet_vty *vty, const char *buf, size_t bufsize)
{
	return write(vty->vty_sock, buf, bufsize);
}

int knet_vty_write(struct knet_vty *vty, const char *format, ...)
{
	va_list args;
	int len = 0;
	char buf[VTY_MAX_BUFFER_SIZE];

	if (!vty) {
		errno = EINVAL;
		return -1;
	}

	va_start (args, format);
	len = vsnprintf (buf, VTY_MAX_BUFFER_SIZE, format, args);
	va_end (args);

	if (len < 0)
		return -1;

	return knet_vty_loopy_write(vty, buf, len);
}

static int knet_vty_read_real(struct knet_vty *vty, unsigned char *buf, size_t bufsize,
			      int ignore_iac)
{
	ssize_t readlen;

iac_retry:
	readlen = read(vty->vty_sock, buf, bufsize);
	if (readlen < 0)
		return readlen;

	/* at somepoint we *might* have to add IAC parsing */
	if ((buf[0] == IAC) && (ignore_iac))
		goto iac_retry;

	return readlen;
}

int knet_vty_read(struct knet_vty *vty, unsigned char *buf, size_t bufsize)
{
	if ((!vty) || (!buf) || (bufsize == 0)) {
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
	if (!vty) {
		errno = EINVAL;
		return -1;
	}

	if (on)
		return knet_vty_set_echoon(vty);

	return knet_vty_set_echooff(vty);
}

void knet_vty_print_banner(struct knet_vty *vty)
{
	if (!vty)
		return;

	knet_vty_write(vty,
		"Welcome to " PACKAGE " " PACKAGE_VERSION " (built " __DATE__
		" " __TIME__ ") Management CLI\n");
}
