
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
// #include <openssl/types.h>
// #include <openssl/evp.h>

inline uint64_t rdtsc()
{
   uint32_t hi, lo;
   __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
   return ( (uint64_t)lo)|( ((uint64_t)hi)<<32 );
}

uint64_t platform_random(){
  #pragma message("Platform has no entropy source, this is unsafe. TEST ONLY")
  static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;

  unsigned long cycles;
  #ifdef RISC_V
    asm volatile ("rdcycle %0" : "=r" (cycles));
  #else
    cycles = rdtsc();
  #endif
  

  // from Middle Square Weyl Sequence algorithm
  uint64_t x = cycles;
  x *= x;
  x += (w += s);
  return (x>>32) | (x<<32);
}

void *crypto_memcpy(void *dest, const void *src, size_t count)
{
	char *temp1	  = dest;
	const char *temp2 = src;

	while (count > 0) {
		*temp1++ = *temp2++;
		count--;
	}
	return dest;
}



// uint64_t rand64() {
//   static uint64_t w = 0, s = 0xb5ad4eceda1ce2a9;

//   uint64_t cycles = rdtsc();

//   // from Middle Square Weyl Sequence algorithm
//   uint64_t x = cycles;
//   x *= x;
//   x += (w += s);
//   uint64_t rnd = (x>>32) | (x<<32);
// //   printf("\n0x%lx\n", rnd);
// //   return rnd;
//   return (x>>32) | (x<<32);
// }

int RAND_bytes(unsigned char *buf, int num)
{
    unsigned char *temp = buf;
    while (num-8 >= 0){
        *(uint64_t*)temp = platform_random();
        temp+=8;
        num -= 8;
    }
    if (num > 0)
    {
        uint64_t rand = platform_random();
        crypto_memcpy(temp, &rand, num);
    }
    return 1;
}


int RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_bytes(buf, num);
}
// int main() {
//     unsigned char array[100];
//     for (size_t i = 0; i < 100; i++)
//     {
//         array[i] = 0;
//     }
    
//     RAND_bytes(array, 39);
//     for (size_t i = 0; i < 50; i++)
//     {
//         printf("%x ", array[i]);
//     }

// }
