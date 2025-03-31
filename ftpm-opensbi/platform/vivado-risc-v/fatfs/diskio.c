
#include <sbi/sbi_console.h>

#include "fatfs/ff.h"			/* Obtains integer types */
#include "fatfs/diskio.h"		/* Declarations of disk functions */

/* Definitions of physical drive number for each drive */
#define DEV_RAM		0	/* Example: Map Ramdisk to physical drive 0 */
#define DEV_MMC		1	/* Example: Map MMC/SD card to physical drive 1 */
#define DEV_USB		2	/* Example: Map USB MSD to physical drive 2 */

/*--------------------------------------------------------------------------------------------*/

/* Card type flags (card_type) */
#define CT_MMC          0x01            /* MMC ver 3 */
#define CT_SD1          0x02            /* SD ver 1 */
#define CT_SD2          0x04            /* SD ver 2 */
#define CT_SDC          (CT_SD1|CT_SD2) /* SD */
#define CT_BLOCK        0x08            /* Block addressing */

#define CMD0    (0)             /* GO_IDLE_STATE */
#define CMD1    (1)             /* SEND_OP_COND */
#define CMD2    (2)             /* SEND_CID */
#define CMD3    (3)             /* RELATIVE_ADDR */
#define CMD4    (4)
#define CMD5    (5)             /* SLEEP_WAKE (SDC) */
#define CMD6    (6)             /* SWITCH_FUNC */
#define CMD7    (7)             /* SELECT */
#define CMD8    (8)             /* SEND_IF_COND */
#define CMD9    (9)             /* SEND_CSD */
#define CMD10   (10)            /* SEND_CID */
#define CMD11   (11)
#define CMD12   (12)            /* STOP_TRANSMISSION */
#define CMD13   (13)
#define CMD15   (15)
#define CMD16   (16)            /* SET_BLOCKLEN */
#define CMD17   (17)            /* READ_SINGLE_BLOCK */
#define CMD18   (18)            /* READ_MULTIPLE_BLOCK */
#define CMD19   (19)
#define CMD20   (20)
#define CMD23   (23)
#define CMD24   (24)
#define CMD25   (25)
#define CMD27   (27)
#define CMD28   (28)
#define CMD29   (29)
#define CMD30   (30)
#define CMD32   (32)
#define CMD33   (33)
#define CMD38   (38)
#define CMD42   (42)
#define CMD55   (55)            /* APP_CMD */
#define CMD56   (56)
#define ACMD6   (0x80+6)        /* define the data bus width */
#define ACMD41  (0x80+41)       /* SEND_OP_COND (ACMD) */

// Capability bits
#define SDC_CAPABILITY_SD_4BIT  0x0001
#define SDC_CAPABILITY_SD_RESET 0x0002
#define SDC_CAPABILITY_ADDR     0xff00

// Control bits
#define SDC_CONTROL_SD_4BIT     0x0001
#define SDC_CONTROL_SD_RESET    0x0002

// Card detect bits
#define SDC_CARD_INSERT_INT_EN  0x0001
#define SDC_CARD_INSERT_INT_REQ 0x0002
#define SDC_CARD_REMOVE_INT_EN  0x0004
#define SDC_CARD_REMOVE_INT_REQ 0x0008

// Command status bits
#define SDC_CMD_INT_STATUS_CC   0x0001  // Command complete
#define SDC_CMD_INT_STATUS_EI   0x0002  // Any error
#define SDC_CMD_INT_STATUS_CTE  0x0004  // Timeout
#define SDC_CMD_INT_STATUS_CCRC 0x0008  // CRC error
#define SDC_CMD_INT_STATUS_CIE  0x0010  // Command code check error

// Data status bits
#define SDC_DAT_INT_STATUS_TRS  0x0001  // Transfer complete
#define SDC_DAT_INT_STATUS_ERR  0x0002  // Any error
#define SDC_DAT_INT_STATUS_CTE  0x0004  // Timeout
#define SDC_DAT_INT_STATUS_CRC  0x0008  // CRC error
#define SDC_DAT_INT_STATUS_CFE  0x0010  // Data FIFO underrun or overrun

#define ERR_EOF             30
#define ERR_NOT_ELF         31
#define ERR_ELF_BITS        32
#define ERR_ELF_ENDIANNESS  33
#define ERR_CMD_CRC         34
#define ERR_CMD_CHECK       35
#define ERR_DATA_CRC        36
#define ERR_DATA_FIFO       37
#define ERR_BUF_ALIGNMENT   38

struct sdc_regs {
    volatile uint32_t argument;
    volatile uint32_t command;
    volatile uint32_t response1;
    volatile uint32_t response2;
    volatile uint32_t response3;
    volatile uint32_t response4;
    volatile uint32_t data_timeout;
    volatile uint32_t control;
    volatile uint32_t cmd_timeout;
    volatile uint32_t clock_divider;
    volatile uint32_t software_reset;
    volatile uint32_t power_control;
    volatile uint32_t capability;
    volatile uint32_t cmd_int_status;
    volatile uint32_t cmd_int_enable;
    volatile uint32_t dat_int_status;
    volatile uint32_t dat_int_enable;
    volatile uint32_t block_size;
    volatile uint32_t block_count;
    volatile uint32_t card_detect;
    volatile uint32_t res_50;
    volatile uint32_t res_54;
    volatile uint32_t res_58;
    volatile uint32_t res_5c;
    volatile uint64_t dma_addres;
};

#define MAX_BLOCK_CNT 0x1000

/* Note: .data section not supported in BootROM */

static struct sdc_regs * const regs __attribute__((section(".rodata"))) = (struct sdc_regs *)0x60000000;

int errno __attribute__((section(".bss")));
static DSTATUS drv_status __attribute__((section(".bss")));
static BYTE card_type __attribute__((section(".bss")));
static uint32_t response[4] __attribute__((section(".bss")));
static FATFS fatfs __attribute__((section(".bss")));
static int alt_mem __attribute__((section(".bss")));
static FIL fd __attribute__((section(".bss")));


const char * errno_to_str(void) {
    switch (errno) {
    case FR_OK: return "No error";
    case FR_DISK_ERR: return "Disk I/O error";
    case FR_INT_ERR: return "Assertion failed";
    case FR_NOT_READY: return "Disk not ready";
    case FR_NO_FILE: return "File not found";
    case FR_NO_PATH: return "Path not found";
    case FR_INVALID_NAME: return "Invalid path";
    case FR_DENIED: return "Access denied";
    case FR_EXIST: return "Already exist";
    case FR_INVALID_OBJECT: return "The FS object is invalid";
    case FR_WRITE_PROTECTED: return "The drive is write protected";
    case FR_INVALID_DRIVE: return "The drive number is invalid";
    case FR_NOT_ENABLED: return "The volume has no work area";
    case FR_NO_FILESYSTEM: return "Not a valid FAT volume";
    case FR_MKFS_ABORTED: return "The f_mkfs() aborted";
    case FR_TIMEOUT: return "Timeout";
    case FR_LOCKED: return "Locked";
    case FR_NOT_ENOUGH_CORE: return "Not enough memory";
    case FR_TOO_MANY_OPEN_FILES: return "Too many open files";
    case ERR_EOF: return "Unexpected EOF";
    case ERR_NOT_ELF: return "Not an ELF file";
    case ERR_ELF_BITS: return "Wrong ELF word size";
    case ERR_ELF_ENDIANNESS: return "Wrong ELF endianness";
    case ERR_CMD_CRC: return "Command CRC error";
    case ERR_CMD_CHECK: return "Command code check error";
    case ERR_DATA_CRC: return "Data CRC error";
    case ERR_DATA_FIFO: return "Data FIFO error";
    case ERR_BUF_ALIGNMENT: return "Bad buffer alignment";
    }
    return "Unknown error code";
}

static void usleep(unsigned us) {
    uintptr_t cycles0;
    uintptr_t cycles1;
    asm volatile ("csrr %0, 0xB00" : "=r" (cycles0));
    for (;;) {
        asm volatile ("csrr %0, 0xB00" : "=r" (cycles1));
        if (cycles1 - cycles0 >= us * 100) break;
    }
}

static int sdc_cmd_finish(unsigned cmd) {
    while (1) {
        unsigned status = regs->cmd_int_status;
        if (status) {
            // clear interrupts
            regs->cmd_int_status = 0;
            while (regs->software_reset != 0) {}
            if (status == SDC_CMD_INT_STATUS_CC) {
                // get response
                response[0] = regs->response1;
                response[1] = regs->response2;
                response[2] = regs->response3;
                response[3] = regs->response4;
                return 0;
            }
            errno = FR_DISK_ERR;
            if (status & SDC_CMD_INT_STATUS_CTE) errno = FR_TIMEOUT;
            if (status & SDC_CMD_INT_STATUS_CCRC) errno = ERR_CMD_CRC;
            if (status & SDC_CMD_INT_STATUS_CIE) errno = ERR_CMD_CHECK;
            break;
        }
    }
    return -1;
}

static int sdc_data_finish(void) {
    int status;

    while ((status = regs->dat_int_status) == 0) {}
    regs->dat_int_status = 0;
    while (regs->software_reset != 0) {}

    if (status == SDC_DAT_INT_STATUS_TRS) return 0;
    errno = FR_DISK_ERR;
    if (status & SDC_DAT_INT_STATUS_CTE) errno = FR_TIMEOUT;
    if (status & SDC_DAT_INT_STATUS_CRC) errno = ERR_DATA_CRC;
    if (status & SDC_DAT_INT_STATUS_CFE) errno = ERR_DATA_FIFO;
    return -1;
}


static int send_data_cmd(unsigned cmd, unsigned arg, void * buf, unsigned blocks) {
    unsigned command = (cmd & 0x3f) << 8;
    switch (cmd) {
    case CMD0:
    case CMD4:
    case CMD15:
        // No responce
        break;
    case CMD11:
    case CMD13:
    case CMD16:
    case CMD17:
    case CMD18:
    case CMD19:
    case CMD23:
    case CMD24:
    case CMD25:
    case CMD27:
    case CMD30:
    case CMD32:
    case CMD33:
    case CMD42:
    case CMD55:
    case CMD56:
    case ACMD6:
        // R1
        command |= 1; // 48 bits
        command |= 1 << 3; // resp CRC
        command |= 1 << 4; // resp OPCODE
        break;
    case CMD7:
    case CMD12:
    case CMD20:
    case CMD28:
    case CMD29:
    case CMD38:
        // R1b
        command |= 1; // 48 bits
        command |= 1 << 2; // busy
        command |= 1 << 3; // resp CRC
        command |= 1 << 4; // resp OPCODE
        break;
    case CMD2:
    case CMD9:
    case CMD10:
        // R2
        command |= 2; // 136 bits
        command |= 1 << 3; // resp CRC
        break;
    case ACMD41:
        // R3
        command |= 1; // 48 bits
        break;
    case CMD3:
        // R6
        command |= 1; // 48 bits
        command |= 1 << 2; // busy
        command |= 1 << 3; // resp CRC
        command |= 1 << 4; // resp OPCODE
        break;
    case CMD8:
        // R7
        command |= 1; // 48 bits
        command |= 1 << 3; // resp CRC
        command |= 1 << 4; // resp OPCODE
        break;
    }

    if (blocks) {
        command |= 1 << 5;
        if ((intptr_t)buf & 3) {
            errno = ERR_BUF_ALIGNMENT;
            return -1;
        }
        regs->dma_addres = (uint64_t)(intptr_t)buf;
        regs->block_size = 511;
        regs->block_count = blocks - 1;
        regs->data_timeout = 0xFFFFFF;
    }

    regs->command = command;
    regs->cmd_timeout = 0xFFFFF;
    regs->argument = arg;

    if (sdc_cmd_finish(cmd) < 0) return -1;
    if (blocks) return sdc_data_finish();

    return 0;
}


static int send_data_cmd_r(unsigned cmd, unsigned arg, void * buf, unsigned blocks) {
    unsigned command = (cmd & 0x3f) << 8;

    // R1
    command |= 1; // 48 bits
    command |= 1 << 3; // resp CRC
    command |= 1 << 4; // resp OPCODE

    if (blocks) {
        command |= 1 << 5;
        
        if ((intptr_t)buf & 3) {
            errno = ERR_BUF_ALIGNMENT;
            return -1;
        }
        regs->dma_addres = (uint64_t)(intptr_t)buf;
        regs->block_size = 511;
        regs->block_count = blocks - 1;
        regs->data_timeout = 0xFFFFFF;
    }

    regs->command = command;
    regs->cmd_timeout = 0xFFFFF;
    regs->argument = arg;

    if (sdc_cmd_finish(cmd) < 0) return -1;
    if (blocks) return sdc_data_finish();

    return 0;
}

static int send_data_cmd_w(unsigned cmd, unsigned arg, const void * buf, unsigned blocks) {
    unsigned command = (cmd & 0x3f) << 8;

    // R1
    command |= 1; // 48 bits
    // command |= 1 << 2;
    command |= 1 << 3; // resp CRC
    command |= 1 << 4; // resp OPCODE

    if (blocks) {
        command |= 1 << 6;
        
        if ((intptr_t)buf & 3) {
            errno = ERR_BUF_ALIGNMENT;
            sbi_printf("[fTPM] send_data_cmd_w(): ERR_BUF_ALIGNMENT!!!\n");
            return -1;
        }
        regs->dma_addres = (uint64_t)(intptr_t)buf;
        regs->block_size = 511;
        regs->block_count = blocks - 1;

        // uint64_t timeout = (uint64_t)blocks * 512 * 8 / 1;
        // timeout += (uint64_t)25000000 / 1000 * blocks;
        // timeout += (uint64_t)25000000 / 100; // 10ms
        // if (timeout > 0xffffff) timeout = 0;

        // regs->data_timeout = timeout;

        regs->data_timeout = 0xFFFFFF;
    }

    regs->command = command;
    regs->cmd_timeout = 0xFFFFF;
    regs->argument = arg;

    if (sdc_cmd_finish(cmd) < 0) return -1;
    if (blocks) return sdc_data_finish();

    return 0;
}

#define send_cmd(cmd, arg) send_data_cmd(cmd, arg, NULL, 0)



static int ini_sd(void) {
    unsigned rca;

    /* Reset controller */
    regs->software_reset = 1;
    while ((regs->software_reset & 1) == 0) {}
    regs->clock_divider = 0x7c;
    regs->software_reset = 0;
    while (regs->software_reset) {}
    usleep(5000);

    card_type = 0;
    drv_status = STA_NOINIT;

    if (regs->capability & SDC_CAPABILITY_SD_RESET) {
        /* Power cycle SD card */
        regs->control |= SDC_CONTROL_SD_RESET;
        usleep(1000000);
        regs->control &= ~SDC_CONTROL_SD_RESET;
        usleep(100000);
    }

    /* Enter Idle state */
    send_cmd(CMD0, 0);

    card_type = CT_SD1;
    if (send_cmd(CMD8, 0x1AA) == 0) {
        if ((response[0] & 0xfff) != 0x1AA) {
            errno = ERR_CMD_CHECK;
            return -1;
        }
        card_type = CT_SD2;
    }

    /* Wait for leaving idle state (ACMD41 with HCS bit) */
    while (1) {
        /* ACMD41, Set Operating Conditions: Host High Capacity & 3.3V */
        if (send_cmd(CMD55, 0) < 0 || send_cmd(ACMD41, 0x40300000) < 0) return -1;
        if (response[0] & (1 << 31)) {
            if (response[0] & (1 << 30)) card_type |= CT_BLOCK;
            break;
        }
    }

    /* Enter Identification state */
    if (send_cmd(CMD2, 0) < 0) return -1;

    /* Get RCA (Relative Card Address) */
    rca = 0x1234;
    if (send_cmd(CMD3, rca << 16) < 0) return -1;
    rca = response[0] >> 16;

    /* Select card */
    if (send_cmd(CMD7, rca << 16) < 0) return -1;

    /* Clock 25MHz */
    regs->clock_divider = 3;
    usleep(10000);

    /* Bus width 1-bit */
    regs->control = 0;
    if (send_cmd(CMD55, rca << 16) < 0 || send_cmd(ACMD6, 0) < 0) return -1;

    /* Set R/W block length to 512 */
    if (send_cmd(CMD16, 512) < 0) return -1;

    drv_status &= ~STA_NOINIT;
    return 0;
}



DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive nmuber to identify the drive */
)
{
	// DSTATUS stat;
	// int result;

	// switch (pdrv) {
	// case DEV_RAM :
	// 	result = RAM_disk_initialize();

	// 	// translate the reslut code here

	// 	return stat;

	// case DEV_MMC :
	// 	result = MMC_disk_initialize();

	// 	// translate the reslut code here

	// 	return stat;

	// case DEV_USB :
	// 	result = USB_disk_initialize();

	// 	// translate the reslut code here

	// 	return stat;
	// }
	// return STA_NOINIT;

    if (ini_sd() < 0) sbi_printf("Cannot access SD: %s\n", errno_to_str());
    return drv_status;
}

DSTATUS disk_status(BYTE drv) {
    return drv_status;
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read */
)
{
	// DRESULT res;
	// int result;

	// switch (pdrv) {
	// case DEV_RAM :
	// 	// translate the arguments here

	// 	result = RAM_disk_read(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;

	// case DEV_MMC :
	// 	// translate the arguments here

	// 	result = MMC_disk_read(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;

	// case DEV_USB :
	// 	// translate the arguments here

	// 	result = USB_disk_read(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;
	// }

	// return RES_PARERR;

    if (!count) return RES_PARERR;
    if (drv_status & STA_NOINIT) return RES_NOTRDY;

    // sbi_printf("[fTPM] disk_read(): buff=%p, sector=%x, count=%x\n", buff, sector, count);
    /* Convert LBA to byte address if needed */
    if (!(card_type & CT_BLOCK)) sector *= 512;
    while (count > 0) {
        UINT bcnt = count > MAX_BLOCK_CNT ? MAX_BLOCK_CNT : count;
        unsigned bytes = bcnt * 512;
        if (send_data_cmd_r(bcnt == 1 ? CMD17 : CMD18, sector, buff, bcnt) < 0) return RES_ERROR;
        if (bcnt > 1 && send_cmd(CMD12, 0) < 0) return RES_ERROR;
        sector += (card_type & CT_BLOCK) ? bcnt : bytes;
        count -= bcnt;
        buff += bytes;
    }

    return RES_OK;
}



/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
	// DRESULT res;
	// int result;

	// switch (pdrv) {
	// case DEV_RAM :
	// 	// translate the arguments here

	// 	result = RAM_disk_write(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;

	// case DEV_MMC :
	// 	// translate the arguments here

	// 	result = MMC_disk_write(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;

	// case DEV_USB :
	// 	// translate the arguments here

	// 	result = USB_disk_write(buff, sector, count);

	// 	// translate the reslut code here

	// 	return res;
	// }

	// return RES_PARERR;

    if (!count) return RES_PARERR;
    if (drv_status & STA_NOINIT) return RES_NOTRDY;

    // sbi_printf("[fTPM] disk_write(): buff=%p, sector=%x, count=%x\n", buff, sector, count);

    /* Convert LBA to byte address if needed */
    if (!(card_type & CT_BLOCK)) sector *= 512;
    for (UINT i = 0; i < count; ++i) {
        UINT bcnt = count > MAX_BLOCK_CNT ? MAX_BLOCK_CNT : count;
        unsigned bytes = bcnt * 512;
        if (send_data_cmd_w(bcnt == 1 ? CMD24 : CMD25, sector, buff, bcnt) < 0) return RES_ERROR;
        if (bcnt > 1 && send_cmd(CMD12, 0) < 0) return RES_ERROR;
        sector += (card_type & CT_BLOCK) ? bcnt : bytes;
        count -= bcnt;
        buff += bytes;
    }

    return RES_OK; // Successfully written
}

#endif


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{
	DRESULT res;
	int result;

    sbi_printf("[FATFS] disk_ioctl(): cmd=%x\n", cmd);

	switch (pdrv) {
	case DEV_RAM :

		// Process of the command for the RAM drive

		return res;

	case DEV_MMC :

		// Process of the command for the MMC/SD card

		return res;

	case DEV_USB :

		// Process of the command the USB drive

		return res;
	}

	return RES_PARERR;
}

