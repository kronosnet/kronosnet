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
static int knet_vty_loopy_write(int vty_sock, const char *buf, size_t bufsize)
{
	return write(vty_sock, buf, bufsize);
}

int knet_vty_write(int vty_sock, const char *format, ...)
{
	va_list args;
	int len = 0;
	char buf[VTY_MAX_BUFFER_SIZE];

	if (!vty_sock) {
		errno = EINVAL;
		return -1;
	}

	va_start (args, format);
	len = vsnprintf (buf, VTY_MAX_BUFFER_SIZE, format, args);
	va_end (args);

	if (len < 0)
		return -1;

	return knet_vty_loopy_write(vty_sock, buf, len);
}

static int knet_vty_read_real(int vty_sock, unsigned char *buf, size_t bufsize,
			      int ignore_iac)
{
	ssize_t readlen;

iac_retry:
	readlen = read(vty_sock, buf, bufsize);
	if (readlen < 0)
		return readlen;

	/* at somepoint we *might* have to add IAC parsing */
	if ((buf[0] == IAC) && (ignore_iac))
		goto iac_retry;

	return readlen;
}

int knet_vty_read(int vty_sock, unsigned char *buf, size_t bufsize)
{
	if ((!vty_sock) || (!buf) || (bufsize == 0)) {
		errno = EINVAL;
		return -1;
	}
	return knet_vty_read_real(vty_sock, buf, bufsize, 1);
}

static int knet_vty_set_echooff(int vty_sock)
{
	unsigned char cmdreply[VTY_MAX_BUFFER_SIZE];
	unsigned char cmdechooff[] = { IAC, WILL, TELOPT_ECHO, '\0' };
	unsigned char cmdechooffreply[] = { IAC, DO, TELOPT_ECHO, '\0' };
	ssize_t readlen;

	if (knet_vty_write(vty_sock, "%s", cmdechooff) < 0)
		return -1;

	readlen = knet_vty_read_real(vty_sock, cmdreply, VTY_MAX_BUFFER_SIZE, 0);
	if (readlen < 0)
		return readlen;

	if (memcmp(&cmdreply, &cmdechooffreply, readlen))
		return -1;

	return 0;
}

static int knet_vty_set_echoon(int vty_sock)
{
	unsigned char cmdreply[VTY_MAX_BUFFER_SIZE];
	unsigned char cmdechoon[] = { IAC, WONT, TELOPT_ECHO, '\0' };
	unsigned char cmdechoonreply[] = { IAC, DONT, TELOPT_ECHO, '\0' };
	ssize_t readlen;

	if (knet_vty_write(vty_sock, "%s", cmdechoon) < 0)
		return -1;

	readlen = knet_vty_read_real(vty_sock, cmdreply, VTY_MAX_BUFFER_SIZE, 0);
	if (readlen < 0)
		return readlen;

	if (memcmp(&cmdreply, &cmdechoonreply, readlen))
		return -1;

	return 0;
}

int knet_vty_set_echo(int vty_sock, int on)
{
	if (!vty_sock) {
		errno = EINVAL;
		return -1;
	}

	if (on)
		return knet_vty_set_echoon(vty_sock);

	return knet_vty_set_echooff(vty_sock);
}

void knet_vty_print_banner(int vty_sock)
{
	if (!vty_sock)
		return;

	knet_vty_write(vty_sock,
		"Welcome to " PACKAGE " " PACKAGE_VERSION " (built " __DATE__
		" " __TIME__ ") Management CLI\n");
}
