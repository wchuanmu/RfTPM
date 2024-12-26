#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "rtpm_user.h"

#define RTPM_DEV_PATH "/dev/utpm"

// ./rtpm-controller acquire 1 32767

int main(int argc, char **argv) {

  char *type;
  unsigned long tid;
  unsigned long pfn = 0x80000000;

  struct rtpm_ioctl_tee_acquire tee_acquire;

  type = argv[1];
  tid = atoi(argv[2]);
  pfn = atoi(argv[3]);

  printf("[RTPM-CONTROLLER] type=%s, tid=%lx, pfn=%lx\n", type, tid, pfn);

  int fd = open(RTPM_DEV_PATH, O_RDWR);
  if (fd < 0) {
    printf("cannot open device file\n");
    return -1;
  }

  if (strcmp(type, "acquire") == 0) {
    tee_acquire.tid = tid;
    tee_acquire.pfn = pfn;

    if (ioctl(fd, RTPM_IOC_TEE_ACQUIRE, &tee_acquire) < 0) {
      printf("ioctl failed\n");
      return -1;
    }
  }

  close(fd);
}