//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <asm/sbi.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/string.h>

#include "ftpm.h"
#include "ftpm-sbi.h"
#include "ftpm_user.h"

unsigned long ftpm_tid;
unsigned long state_pfn;

void *state_vaddr;

struct ftpm_cmd {
  uint32_t length;
  uint8_t buffer[];
};

int ftpm_run_command(struct tss_ftpm_context* cnx)
{
  struct sbiret ret;

  ret = sbi_sm_ftpm_run_command(cnx);

  return 0;
}


long ftpm_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[64];

  size_t ioc_size;

  if (!arg)
    return -EINVAL;

  ioc_size = _IOC_SIZE(cmd);
  ioc_size = ioc_size > sizeof(data) ? sizeof(data) : ioc_size;

  if (copy_from_user(data, (void __user *)arg, ioc_size)) {
    return -EFAULT;
  }

  switch (cmd) {
    case FTPM_IOC_RUN_COMMAND:
      ret = ftpm_run_command((struct tss_ftpm_context*)data);
    break;

  default:
    return -ENOSYS;
  }

  if (copy_to_user((void __user *)arg, data, ioc_size)) {
    return -EFAULT;
  }

  return ret;
}