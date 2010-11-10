#include "config.h"

#include <pthread.h>

#include "cfg.h"
#include "knet.h"
#include "utils.h"

static pthread_mutex_t knet_cfg_mutex = PTHREAD_MUTEX_INITIALIZER;

struct knet_cfg *knet_get_iface(const char *name, const int namelen, int create)
{
	struct knet_cfg *knet_iface = knet_cfg_head.knet_cfg;
	char iface[IFNAMSIZ];
	int found = 0;

	pthread_mutex_lock(&knet_cfg_mutex);

	memset(iface, 0, sizeof(iface));
	strncpy(iface, name, namelen);

	while (knet_iface != NULL) {
		if (!strcmp(knet_iface->name, iface)) {
			found = 1;
			break;
		}
		knet_iface = knet_iface->next;
	}

	if ((!found) && (create)) {
		knet_iface = malloc(sizeof(struct knet_cfg));
		if (!knet_iface)
			goto out_clean;

		memset(knet_iface, 0, sizeof(struct knet_cfg));
		memcpy(knet_iface->name, name, namelen);

		knet_iface->next = knet_cfg_head.knet_cfg;
		knet_cfg_head.knet_cfg = knet_iface;
	}

out_clean:
	pthread_mutex_unlock(&knet_cfg_mutex);

	return knet_iface;
}

void knet_destroy_iface(struct knet_cfg *knet_iface)
{
	struct knet_cfg *knet_iface_tmp = knet_cfg_head.knet_cfg;
	struct knet_cfg *knet_iface_prev = knet_cfg_head.knet_cfg;

	pthread_mutex_lock(&knet_cfg_mutex);

	while (knet_iface_tmp != knet_iface) {
		knet_iface_prev = knet_iface_tmp;
		knet_iface_tmp = knet_iface_tmp->next;
	}

	if (knet_iface_tmp == knet_iface) {
		if (knet_iface_tmp == knet_iface_prev) {
			knet_cfg_head.knet_cfg = knet_iface_tmp->next;
		} else {
			knet_iface_prev->next = knet_iface_tmp->next;
		}
		free(knet_iface);
	}

	pthread_mutex_unlock(&knet_cfg_mutex);
}

int knet_read_config(void)
{
	int err = 0;

	pthread_mutex_lock(&knet_cfg_mutex);

	pthread_mutex_unlock(&knet_cfg_mutex);
	return err;
}

int knet_write_config(void)
{
	int err = 0;

	pthread_mutex_lock(&knet_cfg_mutex);

	pthread_mutex_unlock(&knet_cfg_mutex);
	return err;
}
