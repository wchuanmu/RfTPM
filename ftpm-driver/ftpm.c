
#include "ftpm.h"
#include "ftpm-sbi.h"

#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>

#define   DRV_DESCRIPTION   "ftpm"
#define   DRV_VERSION       "1.0.0"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("iwangjye@gmail.com");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

static const struct file_operations ftpm_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = ftpm_ioctl,
};


struct miscdevice ftpm_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "ftpm",
  .fops = &ftpm_fops,
  .mode = 0666,
};


static int __init ftpm_dev_init(void)
{
  int  ret;


  ret = misc_register(&ftpm_dev);
  if (ret < 0)
  {
    pr_err("[fTPM-DRIVER] misc_register() failed\n");
  }

  ftpm_dev.this_device->coherent_dma_mask = DMA_BIT_MASK(32);

  pr_info("[fTPM-DRIVER] " DRV_DESCRIPTION " v" DRV_VERSION "\n");

  return ret;
}


static void __exit ftpm_dev_exit(void)
{
  pr_info("[fTPM-DRIVER] ftpm_dev_exit()\n");
  misc_deregister(&ftpm_dev); 
  return;
}

module_init(ftpm_dev_init);
module_exit(ftpm_dev_exit);
