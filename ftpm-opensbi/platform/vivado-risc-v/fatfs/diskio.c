
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