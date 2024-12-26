#ifndef _FTPM_SBI_H_
#define _FTPM_SBI_H_

#include <asm/sbi.h>
#include "ftpm_user.h"


struct sbiret sbi_sm_ftpm_run_command(struct tss_ftpm_context *cnx);
#endif