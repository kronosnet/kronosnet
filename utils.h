#ifndef __UTILS_H__
#define __UTILS_H__

extern int do_read(int fd, void *buf, size_t count);
extern int do_write(int fd, void *buf, size_t count);
extern int str_explode(char *src, char **dest, int *pos);

#endif
