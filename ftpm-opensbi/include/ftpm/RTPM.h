#ifndef RTPM_H
#define RTPM_H
#include <stdint.h>

struct rtpm_cmd {
  uint32_t length;
  uint8_t buffer[];
};


int rtpm_cmd_handler(struct rtpm_cmd *cmd);

int fake_main(uint64_t dummy, uint64_t dramAddr, uint64_t dramSize, uint64_t freeAddr, uint64_t utmAddr, uint64_t utmSize);

#endif