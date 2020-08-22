#ifndef __KERNEL__
#define __KERNEL__
#endif
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/kthread.h>

extern int dprintf(int fd, const char *format, ...);

int main(__maybe_unused int argc, __maybe_unused char **argv) {
  dprintf(1, "%lu\n",THREAD_SIZE);
  return 0;
}
