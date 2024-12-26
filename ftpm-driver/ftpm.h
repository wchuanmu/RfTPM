//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _FTPM_H_
#define _FTPM_H_







#include <asm/sbi.h>
#include <asm/csr.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>
#include <linux/types.h>
#include <linux/file.h>









// /* IMPORTANT: This code assumes Sv39 */
// // #include "riscv64.h"

// #define PAGE_UP(addr)	(((addr)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))
// #define MAX_COMMAND_SIZE		4096	/* maximum size of a command */
// #define MAX_RESPONSE_SIZE		4096	/* maximum size of a response */

// #define TPM_SEND_COMMAND            8

// typedef uintptr_t vaddr_t;
// typedef uintptr_t paddr_t;

// extern struct miscdevice rtpm_dev;
// extern struct rtpm_sbi_communication_t *cm;


// int rtpm_mmap(struct file *filp, struct vm_area_struct *vma);
// long rtpm_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
// // ssize_t rtpm_read (struct file *, char __user *buffer, size_t length, loff_t *);
// // ssize_t rtpm_write (struct file *, const char __user *buffer, size_t length, loff_t *);


// // struct sbiret sbi_rtpm_tee_acquire(unsigned long tid, unsigned long addr);

// int rtpm_tee_acquire(unsigned long data);

long ftpm_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);

#define rtpm_info(fmt, ...) \
  pr_info("rtpm: " fmt, ##__VA_ARGS__)
#define rtpm_err(fmt, ...) \
  pr_err("rtpm: " fmt, ##__VA_ARGS__)
#define rtpm_warn(fmt, ...) \
  pr_warn("rtpm: " fmt, ##__VA_ARGS__)
#endif
