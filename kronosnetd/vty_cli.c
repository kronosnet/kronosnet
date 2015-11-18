/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>

#include "logging.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

/* if this code looks like quagga lib/vty.c it is because we stole it in good part */

#define CONTROL(X)	((X) - '@')
#define VTY_NORMAL	0
#define VTY_PRE_ESCAPE	1
#define VTY_ESCAPE	2
#define VTY_EXT_ESCAPE	3

static void knet_vty_reset_buf(struct knet_vty *vty)
{
	memset(vty->line, 0, sizeof(vty->line));
	vty->line_idx = 0;
	vty->cursor_pos = 0;
	vty->history_pos = vty->history_idx;
}

static void knet_vty_add_to_buf(struct knet_vty *vty, unsigned char *buf, int pos)
{
	char outbuf[2];
	int i;

	if (vty->cursor_pos == vty->line_idx) {
		vty->line[vty->line_idx] = buf[pos];
		vty->line_idx++;
		vty->cursor_pos++;
	} else {
		if (!vty->insert_mode) {
			memmove(&vty->line[vty->cursor_pos+1], &vty->line[vty->cursor_pos],
				vty->line_idx - vty->cursor_pos);
			vty->line_idx++;
		}
		vty->line[vty->cursor_pos] = buf[pos];
		vty->cursor_pos++;
	}

	outbuf[0] = buf[pos];
	outbuf[1] = 0;
	knet_vty_write(vty, "%s%s", outbuf, &vty->line[vty->cursor_pos]);
	for (i = 0; i < (vty->line_idx - vty->cursor_pos); i++)
		knet_vty_write(vty, "%s", telnet_backward_char);
}

static void knet_vty_forward_char(struct knet_vty *vty)
{
	char buf[2];

	if (vty->cursor_pos < vty->line_idx) {
		buf[0] = vty->line[vty->cursor_pos];
		buf[1] = 0;
		knet_vty_write(vty, "%s", buf);
		vty->cursor_pos++;
	}
}

static void knet_vty_backward_char(struct knet_vty *vty)
{
	if (vty->cursor_pos > 0) {
		knet_vty_write(vty, "%s", telnet_backward_char);
		vty->cursor_pos--;
	}
}

static void knet_vty_kill_line(struct knet_vty *vty)
{
	int size, i;

	size = vty->line_idx - vty->cursor_pos;

	if (size == 0)
		return;

	for (i = 0; i < size; i++)
		knet_vty_write(vty, " ");

	for (i = 0; i < size; i++)
		knet_vty_write(vty, "%s", telnet_backward_char);

	memset(&vty->line[vty->cursor_pos], 0, size);
	vty->line_idx = vty->cursor_pos;
}

static void knet_vty_newline(struct knet_vty *vty)
{
	knet_vty_write(vty, "%s", telnet_newline);
	knet_vty_reset_buf(vty);
	knet_vty_prompt(vty);
}

static void knet_vty_delete_char(struct knet_vty *vty)
{
	int size, i;

	if (vty->line_idx == 0) {
		knet_vty_exit_node(vty);
		if (!vty->got_epipe) {
			knet_vty_newline(vty);
		}
		return;
	}

	if (vty->line_idx == vty->cursor_pos)
		return;

	size = vty->line_idx - vty->cursor_pos;

	vty->line_idx--;
	memmove(&vty->line[vty->cursor_pos], &vty->line[vty->cursor_pos+1],
		size - 1);
	vty->line[vty->line_idx] = '\0';

	knet_vty_write(vty, "%s ", &vty->line[vty->cursor_pos]);
	for (i = 0; i < size; i++)
		knet_vty_write(vty, "%s", telnet_backward_char);
}

static void knet_vty_delete_backward_char(struct knet_vty *vty)
{
	if (vty->cursor_pos == 0)
		return;

	knet_vty_backward_char(vty);
	knet_vty_delete_char(vty);
}

static void knet_vty_beginning_of_line(struct knet_vty *vty)
{
	while (vty->cursor_pos != 0)
		knet_vty_backward_char(vty);
}

static void knet_vty_end_of_line(struct knet_vty *vty)
{
	while (vty->cursor_pos != vty->line_idx)
		knet_vty_forward_char(vty);
}

static void knet_vty_kill_line_from_beginning(struct knet_vty *vty)
{
	knet_vty_beginning_of_line(vty);
	knet_vty_kill_line(vty);
}

static void knet_vty_backward_word(struct knet_vty *vty)
{
	while(vty->cursor_pos > 0 && vty->line[vty->cursor_pos - 1] == ' ')
		knet_vty_backward_char(vty);

	while(vty->cursor_pos > 0 && vty->line[vty->cursor_pos - 1] != ' ')
		knet_vty_backward_char(vty);
}

static void knet_vty_forward_word(struct knet_vty *vty)
{
	while(vty->cursor_pos != vty->line_idx && vty->line[vty->cursor_pos] == ' ')
		knet_vty_forward_char(vty);

	while(vty->cursor_pos != vty->line_idx && vty->line[vty->cursor_pos] != ' ')
		knet_vty_forward_char(vty);
}

static void knet_vty_backward_kill_word(struct knet_vty *vty)
{
	while(vty->cursor_pos > 0 && vty->line[vty->cursor_pos - 1] == ' ')
		knet_vty_delete_backward_char(vty);

	while(vty->cursor_pos > 0 && vty->line[vty->cursor_pos - 1] != ' ')
		knet_vty_delete_backward_char(vty);
}

static void knet_vty_forward_kill_word(struct knet_vty *vty)
{
	while(vty->cursor_pos != vty->line_idx && vty->line[vty->cursor_pos] == ' ')
		knet_vty_delete_char(vty);

	while(vty->cursor_pos != vty->line_idx && vty->line[vty->cursor_pos] != ' ')
		knet_vty_delete_backward_char(vty);
}

static void knet_vty_transpose_chars(struct knet_vty *vty)
{
	unsigned char swap[2];

	if (vty->line_idx < 2 || vty->cursor_pos < 2)
		return;

	swap[0] = vty->line[vty->cursor_pos - 1];
	swap[1] = vty->line[vty->cursor_pos - 2];
	knet_vty_delete_backward_char(vty);
	knet_vty_delete_backward_char(vty);
	knet_vty_add_to_buf(vty, swap, 0);
	knet_vty_add_to_buf(vty, swap, 1);
}

static void knet_vty_history_add(struct knet_vty *vty)
{
	int idx;

	if (knet_vty_is_line_empty(vty))
		return;

	idx = vty->history_idx % KNET_VTY_MAX_HIST;

	if (vty->history[idx]) {
		free(vty->history[idx]);
		vty->history[idx] = NULL;
	}

	vty->history[idx] = strdup(vty->line);
	if (vty->history[idx] == NULL) {
		log_error("Not enough memory to add history lines!");
		knet_vty_write(vty, "Not enough memory to add history lines!");
	}

	vty->history_idx++;

	if (vty->history_idx == KNET_VTY_MAX_HIST)
		vty->history_idx = 0;

	vty->history_pos = vty->history_idx;
}

static void knet_vty_history_print(struct knet_vty *vty)
{
	int len;

	knet_vty_kill_line_from_beginning(vty);

	len = strlen(vty->history[vty->history_pos]);
	memcpy(vty->line, vty->history[vty->history_pos], len);
	vty->cursor_pos = vty->line_idx = len;

	knet_vty_write(vty, "%s", vty->line);
}

static void knet_vty_history_prev(struct knet_vty *vty)
{
	int idx;

	idx = vty->history_pos;

	if (idx == 0) {
		idx = KNET_VTY_MAX_HIST - 1;
	} else {
		idx--;
	}

	if (vty->history[idx] == NULL)
		return;

	vty->history_pos = idx;

	knet_vty_history_print(vty);
}

static void knet_vty_history_next(struct knet_vty *vty)
{
	int idx;

	if (vty->history_pos == vty->history_idx)
		return;

	idx = vty->history_pos;

	if (idx == (KNET_VTY_MAX_HIST - 1)) {
		idx = 0;
	} else {
		idx++;
	}

	if (vty->history[idx] == NULL) {
		knet_vty_kill_line_from_beginning(vty);
		vty->history_pos = vty->history_idx;
		return;
	}

	vty->history_pos = idx;

	knet_vty_history_print(vty);
}

static int knet_vty_process_buf(struct knet_vty *vty, unsigned char *buf, int buflen)
{
	int i;

	if (vty->line_idx >= KNET_VTY_MAX_LINE)
		return -1;

	for (i = 0; i < buflen; i++) {
		if (vty->escape == VTY_EXT_ESCAPE)  {
			if (buf[i] != '~')
				goto vty_ext_escape_out;

			switch (vty->escape_code) {
				case ('1'):
					knet_vty_beginning_of_line(vty);
					break;
				case ('2'):
					if (!vty->insert_mode) {
						vty->insert_mode = 1;
					} else {
						vty->insert_mode = 0;
					}
					break;
				case ('3'):
					knet_vty_delete_char(vty);
					break;
				case ('4'):
					knet_vty_end_of_line(vty);
					break;
				case ('5'):
					knet_vty_history_prev(vty);
					break;
				case ('6'):
					knet_vty_history_next(vty);
					break;
			}

vty_ext_escape_out:
			vty->escape = VTY_NORMAL;
			continue;
		}

		if (vty->escape == VTY_ESCAPE) {
			switch (buf[i]) {
				case ('A'):
					knet_vty_history_prev(vty);
					break;
				case ('B'):
					knet_vty_history_next(vty);
					break;
				case ('C'):
					knet_vty_forward_char(vty);
					break;
				case ('D'):
					knet_vty_backward_char(vty);
					break;
				case ('H'):
					knet_vty_beginning_of_line(vty);
					break;
				case ('F'):
					knet_vty_end_of_line(vty);
					break;
				case ('1'):
				case ('2'):
				case ('3'):
				case ('4'):
				case ('5'):
				case ('6'):
					vty->escape = VTY_EXT_ESCAPE;
					vty->escape_code = buf[i];
					break;
				default:
					break;
			}

			if (vty->escape == VTY_ESCAPE)
				vty->escape = VTY_NORMAL;

			continue;
		}

		if (vty->escape == VTY_PRE_ESCAPE) {
			switch (buf[i]) {
				case 'O':
				case '[':
					vty->escape = VTY_ESCAPE;
					break;
				case 'b':
					vty->escape = VTY_NORMAL;
					knet_vty_backward_word(vty);
					break;
				case 'f':
					vty->escape = VTY_NORMAL;
					knet_vty_forward_word(vty);
					break;
				case 'd':
					vty->escape = VTY_NORMAL;
					knet_vty_forward_kill_word(vty);
					break;
				case CONTROL('H'):
				case 0x7f:
					vty->escape = VTY_NORMAL;
					knet_vty_backward_kill_word(vty);
					break;
				default:
					break;
			}
			continue;
		}

		switch (buf[i]) {
			case CONTROL('A'):
				knet_vty_beginning_of_line(vty);
				break;
			case CONTROL('B'):
				knet_vty_backward_char(vty);
				break;
			case CONTROL('C'):
				knet_vty_newline(vty);
				break;
			case CONTROL('D'):
				knet_vty_delete_char(vty);
				break;
			case CONTROL('E'):
				knet_vty_end_of_line(vty);
				break;
			case CONTROL('F'):
				knet_vty_forward_char(vty);
				break;
			case CONTROL('H'):
			case 0x7f:
				knet_vty_delete_backward_char(vty);
				break;
			case CONTROL('K'):
				knet_vty_kill_line(vty);
				break;
			case CONTROL('N'):
				knet_vty_history_next(vty);
				break;
			case CONTROL('P'):
				knet_vty_history_prev(vty);
				break;
			case CONTROL('T'):
				knet_vty_transpose_chars(vty);
				break;
			case CONTROL('U'):
				knet_vty_kill_line_from_beginning(vty);
				break;
			case CONTROL('W'):
				knet_vty_backward_kill_word(vty);
				break;
			case CONTROL('Z'):
				vty->node = NODE_CONFIG;
				knet_vty_exit_node(vty);
				knet_vty_newline(vty);
				break;
			case '\n':
			case '\r':
				knet_vty_end_of_line(vty);
				knet_vty_write(vty, "%s", telnet_newline);
				knet_vty_history_add(vty);
				knet_vty_execute_cmd(vty);
				knet_vty_reset_buf(vty);
				knet_vty_prompt(vty);
				break;
			case '\t':
				knet_vty_end_of_line(vty);
				knet_vty_tab_completion(vty);
				break;
			case '?':
				knet_vty_end_of_line(vty);
				knet_vty_write(vty, "%s", telnet_newline);
				knet_vty_help(vty);
				knet_vty_prompt(vty);
				knet_vty_write(vty, "%s", vty->line);
				break;
			case '\033':
				vty->escape = VTY_PRE_ESCAPE;
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

	knet_vty_prompt(vty);

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
