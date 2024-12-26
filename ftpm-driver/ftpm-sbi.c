#include "ftpm-sbi.h"

#include "ftpm_user.h"


struct sbiret sbi_sm_ftpm_run_command(struct tss_ftpm_context *cnx) {
  return sbi_ecall(SBI_EXT_EXPERIMENTAL_FTPM,
      SBI_FTPM_RUN_COMMAND,
      (unsigned long) cnx, 0, 0, 0, 0, 0);
}