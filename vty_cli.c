#include "config.h"

#include <errno.h>
#include <sys/select.h>

#include "utils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_utils.h"

static int knet_vty_process_buf(struct knet_vty *vty, unsigned char *buf, int buflen)
{
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

		knet_vty_process_buf(vty, buf, readlen);
	}

out_clean:

	return;
}
