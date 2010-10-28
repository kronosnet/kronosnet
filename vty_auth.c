#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <grp.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "utils.h"
#include "vty_auth.h"
#include "vty_utils.h"

static int knet_pam_misc_conv(int num_msg, const struct pam_message **msgm,
			      struct pam_response **response, void *appdata_ptr)
{
	int count = 0;
	struct pam_response *reply;
	struct knet_vty *vty = (struct knet_vty *)appdata_ptr;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	reply = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));

	if (reply == NULL)
		return PAM_CONV_ERR;

	for (count=0; count < num_msg; ++count) {
		unsigned char readbuf[VTY_MAX_BUFFER_SIZE];
		char *string=NULL;
		int nc;

		memset(readbuf, 0, sizeof(readbuf));

		switch (msgm[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			if (knet_vty_set_echo(vty, 0) < 0) {
				knet_vty_write(vty, "Unable to turn off terminal/telnet echo");
				goto failed_conversation;
			}
			knet_vty_write(vty, "%s", msgm[count]->msg);
			nc = knet_vty_read(vty, readbuf, sizeof(readbuf));
			if (nc < 0)
				goto failed_conversation;
			if (knet_vty_set_echo(vty, 1) < 0) {
				/* doesn't really make a lot of sense tho.... */
				knet_vty_write(vty, "Unable to turn on terminal/telnet echo");
				goto failed_conversation;
			}
			knet_vty_write(vty, "\n");
			readbuf[nc-2] = 0;
			string = strdup((const char*)readbuf);
			if (!string)
				goto failed_conversation;
			break;
		case PAM_PROMPT_ECHO_ON:
			knet_vty_write(vty, "\n%s", msgm[count]->msg);
			nc = knet_vty_read(vty, readbuf, sizeof(readbuf));
			if (nc < 0)
				goto failed_conversation;
			readbuf[nc-2] = 0;
			string = strdup((const char*)readbuf);
			if (!string)
				goto failed_conversation;
			break;
		case PAM_ERROR_MSG:
			log_error("Received PAM error message %s", msgm[count]->msg);
			knet_vty_write(vty, "%s", msgm[count]->msg);
			break;
		case PAM_TEXT_INFO:
			log_error("Received PAM text info: %s", msgm[count]->msg);
			knet_vty_write(vty, "%s", msgm[count]->msg);
			break;
		default:
			if (!vty->got_epipe) {
				log_error("Unknown PAM conversation message");
				knet_vty_write(vty, "Unknown PAM conversation message");
			}
			goto failed_conversation;
		}

		if (string) {
			reply[count].resp_retcode = 0;
			reply[count].resp = string;
			string = NULL;
		}
	}

	*response = reply;
	reply = NULL;

	return PAM_SUCCESS;

failed_conversation:
	if (!vty->got_epipe) {
		log_error("PAM conversation error");
		knet_vty_write(vty, "PAM conversation error");
	}
	if (reply) {
		for (count=0; count < num_msg; ++count) {
			if (reply[count].resp == NULL)
				continue;
			switch (msgm[count]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
			case PAM_PROMPT_ECHO_OFF:
				_pam_overwrite(reply[count].resp);
				free(reply[count].resp);
				break;
			case PAM_BINARY_PROMPT:
				{
					void *bt_ptr = reply[count].resp;
					pam_binary_handler_free(appdata_ptr, bt_ptr);
					break;
				}
			case PAM_ERROR_MSG:
			case PAM_TEXT_INFO:
				free(reply[count].resp);
			}
		}
		free(reply);
		reply = NULL;
	}

	return PAM_CONV_ERR;
}

static int knet_vty_get_pam_user(struct knet_vty *vty, pam_handle_t *pamh)
{
	const void *value;
	int err;

	memset(vty->username, 0, sizeof(vty->username));

	err = pam_get_item(pamh, PAM_USER, &value);

	if (err != PAM_SUCCESS)
		return err;

	strncpy(vty->username, (const char*)value, 32);

	return 0;
}

static int knet_vty_pam_auth_user(struct knet_vty *vty, const char *user)
{
	pam_handle_t *pamh=NULL;
	struct pam_conv conv;
	int err;
	int retry = 1;

	conv.conv = knet_pam_misc_conv;
	conv.appdata_ptr = (void *)vty;

retry_auth:
	err = pam_start("kronosnet", user, &conv, &pamh);
	if (err != PAM_SUCCESS) {
		errno = EINVAL;
		log_error("PAM fatal error: %s", pam_strerror(pamh, err));
		knet_vty_write(vty, "PAM fatal error: %s",
				pam_strerror(pamh, err));
		goto out_fatal;
	}

	err = pam_authenticate(pamh, 0);
	if (err != PAM_SUCCESS) {
		if (vty->got_epipe) {
			errno = EPIPE;
			goto out_fatal;
		} else {
			errno = EINVAL;
			goto out_clean;
		}
	}

	if (knet_vty_get_pam_user(vty, pamh) != PAM_SUCCESS) {
		log_error("PAM: unable to get PAM_USER: %s",
			  pam_strerror(pamh, err));
		knet_vty_write(vty, "PAM: unable to get PAM_USER: %s",
				pam_strerror(pamh, err));
		goto out_clean;
	}

	err = pam_acct_mgmt(pamh, 0);
	if (err != PAM_SUCCESS) {
		log_info("User: %s failed to authenticate on vty(%d) attempt %d",
			 vty->username, vty->conn_num, retry);
		goto out_clean;
	}

out_clean:
	if (pamh) {
		pam_end(pamh, err);
		pamh = NULL;
	}

	if ((err != PAM_SUCCESS) && (retry < AUTH_MAX_RETRY)) {
		retry++;
		goto retry_auth;
	}

out_fatal:
	if (pamh) {
		pam_end(pamh, err);
		pamh = NULL;
	}

	knet_vty_write(vty, "\n");

	return err;
}

static int knet_vty_group_check(struct knet_vty *vty)
{
	struct group grp;
	char *buf;
	size_t buflen;
	long int initlen;
	struct group *result;
	char *gr_mem;
	int err, i;

	errno = 0;
	initlen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if ((initlen < 0) && (errno == EINVAL))
		return -1;

	if (initlen < 0)
		initlen = 1024;

	buflen = (size_t) initlen;

	buf = malloc(buflen);
	if (!buf)
		return -1;

	while ((err = getgrnam_r(DEFAULTADMGROUP, &grp, buf, buflen, &result)) == ERANGE) {
		size_t newlen = 2 * buflen;
		char *newbuf;

		newbuf = realloc(buf, newlen);
		if (!newbuf) {
			err = -1;
			goto out_clean;
		}
		buf = newbuf;
	}
	if (err)
		goto out_clean;

	if (result == NULL) {
		errno = EACCES;
		log_error("No " DEFAULTADMGROUP " group found on the system");
		knet_vty_write(vty, "No " DEFAULTADMGROUP " group found on the system\n");
		err = -1;
		goto out_clean;
	}

	gr_mem = *grp.gr_mem;

	i = 1;
	while(gr_mem != NULL) {
		if (!strcmp(vty->username, gr_mem)) {
			vty->user_can_enable = 1;
			break;
		}
		gr_mem = *(grp.gr_mem + i);
		i++;
	}

out_clean:
	free(buf);

	return err;
}

int knet_vty_auth_user(struct knet_vty *vty, const char *user)
{
	int err;

	err = knet_vty_pam_auth_user(vty, user);
	if (err != PAM_SUCCESS)
		return -1;

	return knet_vty_group_check(vty);
}
