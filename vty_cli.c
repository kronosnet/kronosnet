#include "config.h"

#include <errno.h>
#include <sys/select.h>
#include <unistd.h>

#include "utils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_utils.h"

/* if this code looks like quagga lib/vty.c it is because we stole it in part */

#define CONTROL(X)	((X) - '@')
#define VTY_NORMAL	0
#define VTY_PRE_ESCAPE	1
#define VTY_ESCAPE	2

static const char telnet_backward_char = 0x08;
static const char telnet_space_char = ' ';

/*
 * return = ^M <- 2 chars, go back 2 chars, write 2 spaces, go back 2 chars, go down
 * this feels so old school poke!
 */
static const char telnet_newline[] = { 0x08, 0x08, ' ', ' ', 0x08, 0x08, '\n', 0x0 };

static void knet_vty_reset_buf(struct knet_vty *vty)
{
	memset(vty->line, 0, sizeof(vty->line));
	vty->line_idx = 0;
	vty->cursor_pos = 0;
}

static void knet_vty_add_to_buf(struct knet_vty *vty, unsigned char *buf, int pos)
{
	vty->line[vty->line_idx] = buf[pos];
	vty->line_idx++;
	vty->cursor_pos++;
}

static int knet_vty_process_buf(struct knet_vty *vty, unsigned char *buf, int buflen)
{
	int i;

	if (vty->line_idx >= KNET_VTY_MAX_LINE)
		return -1;

	for (i = 0; i <= buflen; i++) {
		switch (buf[i]) {
			case CONTROL('A'):
				log_info("beginning of line");
				break;
			case CONTROL('B'):
				log_info("backward char");
				break;
			case CONTROL('C'):
				log_info("stop input");
				break;
			case CONTROL('D'):
				log_info("delete char / go one level down");
				break;
			case CONTROL('E'):
				log_info("end of line");
				break;
			case CONTROL('F'):
				log_info("forward char");
				break;
			case CONTROL('H'):
			case 0x7f:
				log_info("delete backward char");
				break;
			case CONTROL('K'):
				log_info("kill line");
				break;
			case CONTROL('N'):
				log_info("next line");
				break;
			case CONTROL('P'):
				log_info("previous line");
				break;
			case CONTROL('T'):
				log_info("transport chars");
				break;
			case CONTROL('U'):
				log_info("kill line from beginning");
				break;
			case CONTROL('W'):
				log_info("kill backward word");
				break;
			case CONTROL('Z'):
				log_info("end config");
				break;
			case '\n':
			case '\r':
				knet_vty_write(vty, "%s", telnet_newline);
				knet_vty_reset_buf(vty);
				break;
			case '\t':
				log_info("command completion");
				break;
			case '?':
				log_info("help");
				break;
			case '\033':
				log_info("escape: %d", buflen);
				break;
			default:
				if (buf[i] > 31 && buf[i] < 127)
					knet_vty_add_to_buf(vty, buf, i);
				break;
		}
	}

	return 0;
}

void knet_vty_cli_bind(struct knet_vty *vty)
{
	int se_result = 0;
	fd_set rfds;
	struct timeval tv;
	unsigned char buf[VTY_MAX_BUFFER_SIZE];
	int readlen;

	while (se_result >= 0 && !vty->got_epipe) {
		FD_ZERO (&rfds);
		FD_SET (vty->vty_sock, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((vty->vty_sock + 1), &rfds, 0, 0, &tv);

		if ((se_result == -1) || (vty->got_epipe))
			goto out_clean;

		if ((se_result == 0) || (!FD_ISSET(vty->vty_sock, &rfds)))
			continue;

		memset(buf, 0 , sizeof(buf));
		readlen = knet_vty_read(vty, buf, sizeof(buf));
		if (readlen <= 0)
			goto out_clean;

		if (knet_vty_process_buf(vty, buf, readlen) < 0) {
			knet_vty_write(vty, "\nError processing command: command too long\n");
			knet_vty_reset_buf(vty);
		}
	}

out_clean:

	return;
}
