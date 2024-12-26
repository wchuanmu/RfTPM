
#ifndef _FTPM_USER_H_
#define _FTPM_USER_H_



// struct rtpm_ioctl_tee_acquire {
//   unsigned long tid;
//   unsigned long pfn;
// };

struct tss_ftpm_context {
    uintptr_t commandBuffer;
    uint32_t written;
    uintptr_t responseBuffer;
    uint32_t read;
};


#define SBI_EXT_EXPERIMENTAL_FTPM 0x08424b45
#define SBI_FTPM_RUN_COMMAND    2001

#define FTPM_IOC_MAGIC 0xa5


#define FTPM_IOC_RUN_COMMAND \
  _IOWR(FTPM_IOC_MAGIC, 0x01, struct tss_ftpm_context)

#endif