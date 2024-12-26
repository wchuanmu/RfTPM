#include <sbi/sbi_trap.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_ecall.h>
// #include "sm-sbi-opensbi.h"
// #include "pmp.h"
// #include "sm-sbi.h"
// #include "sm.h"
// #include "cpu.h"

#include "ftpm.h"

#define SBI_EXT_EXPERIMENTAL_FTPM 0x08424b45
#define SBI_FTPM_RUN_COMMAND    2001


static int sbi_ecall_ftpm_handler(unsigned long extid, unsigned long funcid,
				 const struct sbi_trap_regs *regs,
				 unsigned long *out_val,
				 struct sbi_trap_info *out_trap)
{
  uintptr_t ret;

  // sbi_printf("[SM] TPM sbi_ecall_ftpm_handler()!!!\n");

  switch (funcid) {
    case SBI_FTPM_RUN_COMMAND:
      // ret = sbi_ftpm_run_command(&out->value, regs->a0);
      ret = sbi_ftpm_run_command(0, regs->a0);
      break;
    
    default:
      ret = SBI_ENOTSUPP;
      break;
  }

  return ret;
}

struct sbi_ecall_extension ecall_ftpm = {
  .extid_start = SBI_EXT_EXPERIMENTAL_FTPM,
  .extid_end = SBI_EXT_EXPERIMENTAL_FTPM,
  .handle = sbi_ecall_ftpm_handler,
};
