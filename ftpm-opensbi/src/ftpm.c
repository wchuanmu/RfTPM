#include <sbi/sbi_console.h>
#include <sbi/sbi_ecall.h>
#include <sbi/riscv_encoding.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_hart.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include "string.h"
#include <stdlib.h>
#include "TpmTcpProtocol.h"
#include "simulatorPrivate.h"
#include "ftpm.h"
#include "mprv.h"

#include "intercept.h"
#include "fatfs/ff.h"
#include "fatfs/diskio.h"

#include "openssl/aes.h"
#include "openssl/rand.h"


// #define MAX_BUFFER 1048576
#define MAX_BUFFER 81920

char InputBuffer[MAX_BUFFER];       //The input data buffer for the simulator.
char OutputBuffer[MAX_BUFFER];  

// fs
FATFS fatfs __attribute__((section(".bss")));
extern int errno;

// aes
unsigned char nv_key[128] = "fbcca5ebfc38658e48251d72e9fa5f56";
unsigned char nv_iv[128] = "623e7aa9a2aa92a8ff80fc977462dcc5";

AES_KEY nv_enc_key, nv_dec_key;

// heap
extern char _heap_start;
extern char _heap_end;
static char *heap_ptr = &_heap_start;

extern struct sbi_ecall_extension ecall_ftpm;

static inline unsigned long copy_to_ftpm(void* dst, uintptr_t src, size_t len) {
    int region_overlap = copy_to_sm(dst, src, len);
    if (region_overlap)
    {
        sbi_printf("[FTPM] !!!ERROR!!! in copy_to_ftpm()\n");
    }
    
    if (region_overlap)
        return -1;
    else
        return 0;
}

static inline unsigned long copy_from_ftpm(uintptr_t dst, void* src, size_t len) {
    int region_overlap = copy_from_sm(dst, src, len);
    if (region_overlap)
    {
        sbi_printf("[FTPM] !!!ERROR!!! in copy_from_ftpm()\n");
    }
    
    if (region_overlap)
        return -1;
    else
        return 0;
}


int ftpm_cmd_handler(struct tss_ftpm_context* cnx) {

    uint32_t 		 length;
    uint8_t 		 locality;
    _IN_BUFFER           InBuffer;
    _OUT_BUFFER          OutBuffer;

    locality = 0;
    length = cnx->written;
//   length = cmd->length;
//   memcpy(InputBuffer, cmd->buffer, length);
    csr_set(CSR_MSTATUS, MSTATUS_SUM);
    copy_to_ftpm((void*)InputBuffer, cnx->commandBuffer, length);

	InBuffer.Buffer = (uint8_t *) InputBuffer;
	InBuffer.BufferSize = length;
	OutBuffer.BufferSize = MAX_BUFFER;
	OutBuffer.Buffer = (_OUTPUT_BUFFER) OutputBuffer;

  // umode_printf("[RTPM] rtpm_cmd_handler(): in_buffer_size=%lx\n", InBuffer.BufferSize);
  // for (size_t i = 0; i < InBuffer.BufferSize; i++)
  // {
  //   umode_printf("[RTPM] rtpm_cmd_handler(): in_buffer[%lx]=%x\n", i, InBuffer.Buffer[i]);
  // }
  

	_rpc__Send_Command(locality, InBuffer, &OutBuffer);

//   cmd->length = OutBuffer.BufferSize;
//   memcpy(cmd->buffer, OutBuffer.Buffer, OutBuffer.BufferSize);
    cnx->read = OutBuffer.BufferSize;
    copy_from_ftpm(cnx->responseBuffer, OutBuffer.Buffer, OutBuffer.BufferSize);


    // sbi_printf("[RTPM] rtpm_cmd_handler(): out_buffer_size=%x\n", OutBuffer.BufferSize);
    // for (size_t i = 0; i < OutBuffer.BufferSize; i++)
    // {
    //     sbi_printf("[RTPM] rtpm_cmd_handler(): out_buffer[%lx]=%x\n", i, OutBuffer.Buffer[i]);
    // }

    csr_clear(CSR_MSTATUS, MSTATUS_SUM);

    return 0;
}


unsigned long sbi_ftpm_run_command(unsigned long out, uintptr_t cnx) {

    struct tss_ftpm_context local_cnx;
    unsigned long ret;

    ret = copy_to_ftpm(&local_cnx, cnx, sizeof(struct tss_ftpm_context));
    if (ret)
        return ret;

    ftpm_cmd_handler(&local_cnx);

    ret = copy_from_ftpm(cnx, &local_cnx, sizeof(struct tss_ftpm_context));
    if (ret)
        return ret;

    return ret;
}

// heap
void* _sbrk(ptrdiff_t incr) {
    char *prev_heap_ptr = heap_ptr;
    if (heap_ptr + incr > &_heap_end) {
        // 堆内存溢出
        sbi_printf("[FTPM] !!!HEAP OVERFLOW!!!\n");
        sbi_hart_hang();
        return (void*)-1;
    }
    heap_ptr += incr;
    return (void*)prev_heap_ptr;
}

// aes-cbc
void aes_cbc_encrypt_decrypt(AES_KEY *key, unsigned char *input, unsigned char *output,
                             unsigned char *iv, size_t len, int encrypt) {

    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    if (encrypt) {
        AES_cbc_encrypt(input, output, len, key, iv_copy, AES_ENCRYPT);
    } else {
        AES_cbc_encrypt(input, output, len, key, iv_copy, AES_DECRYPT);
    }
}


static int aes_test() {

    sbi_printf("[fTPM] test AES!!!\n");

    unsigned char plaintext[32] = "Hello, this is a test message!";
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decryptedtext[sizeof(plaintext)];

    int len = sizeof(plaintext);

    aes_cbc_encrypt_decrypt(&nv_enc_key, plaintext, ciphertext, nv_iv, len, 1);

    sbi_printf("Ciphertext:\n");
    for (int i = 0; i < len; i++) {
        sbi_printf("%02x", ciphertext[i]);
    }
    sbi_printf("\n");

    aes_cbc_encrypt_decrypt(&nv_dec_key, ciphertext, decryptedtext, nv_iv, len, 0);

    sbi_printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}


// #if defined(PLATFORM_TYPE) && (PLATFORM_TYPE == 2)


// const char * errno_to_str(void);

// char tmp[100] = "";
// char nvram[32768] = "hello";

// void nvtest(void) {
//     // unsigned char nvram[512];
//     // unsigned char hello[16] = "hello, jay.";



//     // disk_initialize(0);

//     // // if(disk_read(0, nvram, 2050, 1) != RES_OK) sbi_printf("nvtest(): sector_read(0) %s\n", errno_to_str());
//     // // for (size_t i = 0; i < 512; i++)
//     // // {
//     // //     sbi_printf("[nvtest] s[0][%lx]: %x\n", i, nvram[i]);
//     // // }

//     // // if(disk_read(0, nvram, 62333777, 1) != RES_OK) sbi_printf("nvtest(): sector_read(62333777) %s\n", errno_to_str());
//     // // for (size_t i = 0; i < 16; i++)
//     // // {
//     // //     sbi_printf("[nvtest] s[62333777][%lx]: %x\n", i, nvram[i]);
//     // // }

//     // if(disk_write(0, hello, 62330000, 4) != RES_OK) sbi_printf("nvtest(): sector_write(62330000) %s\n", errno_to_str());

//     // if(disk_read(0, nvram, 62330000, 4) != RES_OK) sbi_printf("nvtest(): sector_read(62330000) %s\n", errno_to_str());
//     // for (size_t i = 0; i < 16; i++)
//     // {
//     //     sbi_printf("[nvtest] s[62330000][%lx]: %c\n", i, nvram[i]);
//     // } 

// ///////////////////////////////////////////////////////////////////////////////////////////////////////
    
//     FILE* nvtest = fopen("nvram.bin", FA_CREATE_ALWAYS | FA_READ | FA_WRITE);

//     // FIL nv;
//     // FIL* nvtest = &nv;
//     // errno = f_open((FIL*)nvtest, "nvram.bin", FA_CREATE_ALWAYS | FA_READ | FA_WRITE);
//     // if (errno) sbi_printf("Cannot access SD: %s\n", errno_to_str());


//     UINT bw = fwrite(nvram, 1, NV_MEMORY_SIZE, nvtest);
//     // UINT bw = fwrite(nvram, 1, 20, nvtest);
//     // UINT bw;
//     // f_write((FIL*)nvtest, nvram, 32768, &bw);
//     sbi_printf("[NVTEST] write nvram: bw=%x\n", bw);

//     // f_sync((FIL*)nvtest);
//     frewind(nvtest);

//     fclose(nvtest);

//     //errno = f_open((FIL*)nvtest, "nvram.bin", FA_READ | FA_WRITE);
//     //if (errno) sbi_printf("Cannot access SD: %s\n", errno_to_str());
//     nvtest = fopen("nvram.bin", FA_READ | FA_WRITE);

//     UINT sz = fsize(nvtest);

//     UINT br;
//     br = fread(tmp, 1, 32, nvtest);
//     // f_read((FIL*)nvtest, tmp, 32, &br);
//     sbi_printf("[NVTEST] read nvram: br=%x, size=%x\n", br, sz);

//     sbi_printf("[NVTEST] nvram=%s\n", tmp);

//     fclose(nvtest);

// }
// #endif

static inline uint64_t read_cycle() {
    uint64_t cycle;
    asm volatile ("rdcycle %0" : "=r"(cycle));
    return cycle;
}

void ftpm_init(void) {

    if (AES_set_encrypt_key(nv_key, 128, &nv_enc_key) < 0 
                    || AES_set_decrypt_key(nv_key, 128, &nv_dec_key) < 0) {
        sbi_printf("[fTPM] ftpm_init(): set aes key failed!!!\n");
    }

    // if (AES_set_decrypt_key(nv_key, 128, &nv_dec_key) < 0) {
    //     sbi_printf("AES_set_decrypt_key failed\n");
    // }

    // aes_test();

#if defined(PLATFORM_TYPE) && (PLATFORM_TYPE == 1)
    sbi_printf("[fTPM] ftpm_init(): virt!!!\n");
    _plat__NVEnable(NULL, 0);
    TPM_Manufacture(1);
    _plat__NVDisable((void*)FALSE, 0);

#elif defined(PLATFORM_TYPE) && (PLATFORM_TYPE == 2)
    sbi_printf("[fTPM] ftpm_init(): vivado!!!\n");

    disk_initialize(0);
    errno = f_mount(&fatfs, "", 1);
    if (errno) {
        sbi_printf("[fTPM] ftpm_init(): Cannot mount SD: %s\n", errno_to_str());
    }

	uint64_t begin_cycle = read_cycle();
    _plat__NVEnable(NULL, 0);
	uint64_t end_cycle = read_cycle();
	sbi_printf("[BENCH] _plat__NVEnable(): cycle=%lu\n", end_cycle - begin_cycle);

    if(_plat__NVNeedsManufacture()) {
        sbi_printf("[fTPM] Manufacturing NV state...\n");
	    if(TPM_Manufacture(1) != 0)
		{
		    // if the manufacture didn't work, then make sure that the NV file doesn't
		    // survive. This prevents manufacturing failures from being ignored the
		    // next time the code is run.
		    _plat__NVDisable((void*)TRUE, 0);
            sbi_printf("[fTPM] TPM_Manufacture(1) != 0!!!\n");
		    //exit(1);
		}
    }
    _plat__NVDisable((void*)FALSE, 0);
#else
    sbi_printf("[fTPM] ftpm_init(): unsupported platform!!!\n");
#endif

    _rpc__Signal_PowerOn(FALSE);
    _rpc__Signal_NvOn();
    sbi_printf("[fTPM] ftpm_init(): finished!!!\n");

    sbi_ecall_register_extension(&ecall_ftpm);
}