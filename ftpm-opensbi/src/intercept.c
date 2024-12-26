// #include <time.h>
// #include <stdio.h>
#include <stdint.h>
#include <sbi/sbi_console.h>
#include "intercept.h"

#define RISC_V

int intercept_clock_gettime (clockid_t __clock_id, struct timespec *__tp) {
    uint32_t hi, lo;
  #ifdef RISC_V
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    hi = cycles >> 32;
    lo = cycles;
  #else
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  #endif
   __tp->tv_sec = hi;
   __tp->tv_nsec = lo;
   return 1;
}


int intercept_rand(void) {
  static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;
  unsigned long cycles;
  asm volatile ("rdcycle %0" : "=r" (cycles));
  uint64_t x = cycles;
  x *= x;
  x += (w += s);

  return (int)((x>>32) | (x<<32));
}

#if defined(PLATFORM_TYPE) && (PLATFORM_TYPE == 2)

const char * errno_to_str(void);

// static int errno __attribute__((section(".bss")));

extern int errno;

// static FIL nvram_fd;
FIL nvram_fd;

FILE *intercept_fopen(const char *pathname, BYTE mode) {
  errno = f_open(&nvram_fd, pathname, mode);
  //if (errno) sbi_printf("Cannot access SD: %s\n", errno_to_str());
  if (errno) return NULL;
  //sbi_printf("[debug] intercept_fopen(): pathname=%s, mode=%x, &nvram_fd=%p\n", pathname, mode, (void*)&nvram_fd);
  return (FILE*)&nvram_fd;
}

size_t intercept_fread(void *ptr, size_t size, size_t count, FILE *stream) {

  UINT rd;
  errno = f_read((FIL*)stream, ptr, count*size, &rd);
  //if (errno) sbi_printf("Cannot access SD: %s\n", errno_to_str());
  if (errno) return -1;
  //sbi_printf("[debug] intercept_fread(): &nvram_fd=%p, ptr=%p, btr=%lx, rd=%x\n", (void*)stream, ptr, size*count, rd);
  return rd;
}

size_t intercept_fwrite(const void *ptr, size_t size, size_t count, FILE *stream) {

  UINT bw;
  errno = f_write((FIL*)stream, ptr, count*size, &bw);
  //if (errno) sbi_printf("intercept_fwrite(): %s\n", errno_to_str());
  if (errno) return -1;
  // errno = f_sync((FIL*)stream);
  // if (errno) sbi_printf("intercept_fwrite2(): %s\n", errno_to_str());
  //sbi_printf("[debug] intercept_fwrite(): &nvram_fd=%p, ptr=%p, btw=%lx, bw=%x\n", (void*)stream, ptr, count*size, bw);
  // sbi_printf("[debug] intercept_fwrite(): f_size=%x\n", f_size((FIL*)stream));
  return bw;
}

int intercept_fclose(FILE *stream) {
  //sbi_printf("[debug] intercept_fclose()\n");
  return f_close((FIL*)stream);
}

int intercept_frewind(FILE *stream) {
  //sbi_printf("[debug] intercept_frewind()\n");
  return f_rewind((FIL*)stream);
}

long intercept_fsize(FILE *stream) {
  //sbi_printf("[debug] intercept_fsize()\n");
  return f_size((FIL*)stream);
}

long intercept_ftell(FILE *stream) {
  //sbi_printf("[debug] intercept_ftell()\n");
  return f_tell((FIL*)stream);
}

int intercept_fflush(FILE *stream) {
  //sbi_printf("[debug] intercept_fflush()\n");
  // errno = f_sync((FIL*)stream);
  // if (errno) sbi_printf("Cannot access SD: %s\n", errno_to_str());
  // if (errno) return -1;
  return 0;
}

#endif