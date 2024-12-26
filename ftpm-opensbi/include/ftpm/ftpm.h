#ifndef _FTPM_H_
#define _FTPM_H_

#include "openssl/aes.h"
#include "openssl/rand.h"

struct tss_ftpm_context {
    uintptr_t commandBuffer;
    uint32_t written;
    uintptr_t responseBuffer;
    uint32_t read;
};

extern struct sbi_ecall_extension ecall_ftpm;

extern unsigned char nv_key[128];
extern unsigned char nv_iv[128];

extern AES_KEY nv_enc_key, nv_dec_key;

void uart_putc(char ch);

int uart_getc(void);

void ftpm_init(void);

unsigned long sbi_ftpm_run_command(unsigned long out, unsigned long args);

int ftpm_cmd_handler(struct tss_ftpm_context* cnx);

void aes_cbc_encrypt_decrypt(AES_KEY *key, unsigned char *input, unsigned char *output,
                             unsigned char *iv, size_t len, int encrypt);

void* _sbrk(ptrdiff_t incr);



#endif