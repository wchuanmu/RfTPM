//#include <sbi/sbi_console.h>
#include <stdio.h>
#include "fatfs/ff.h"

#define clock_gettime intercept_clock_gettime
#define rand    intercept_rand

#define fopen intercept_fopen
#define fread intercept_fread
#define fwrite intercept_fwrite
#define fclose intercept_fclose
#define frewind intercept_frewind
#define fsize intercept_fsize
#define ftell intercept_ftell
#define fflush intercept_fflush


int intercept_clock_gettime(clockid_t __clock_id, struct timespec *__tp);
int intercept_rand(void);

FILE *intercept_fopen(const char *pathname, BYTE mode);
size_t intercept_fread(void *ptr, size_t size, size_t count, FILE *stream);
size_t intercept_fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
int intercept_fclose(FILE *stream);
int intercept_frewind(FILE *stream);
long intercept_fsize(FILE *stream);
long intercept_ftell(FILE *stream);
int intercept_fflush(FILE *stream);



// int f_flush(FILE *stream);


// FILE *ff_fopen(const char *filename, const char *mode);
// size_t ff_fread(void *ptr, size_t size, size_t count, FILE *stream);
// size_t ff_fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
// int ff_fseek(FILE *stream, long int offset, int whence);
// int ff_fflush(FILE *stream);