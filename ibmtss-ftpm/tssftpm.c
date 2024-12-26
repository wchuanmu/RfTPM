
#include <linux/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>

#include <ibmtss/TPM_Types.h>
#include <ibmtss/tss.h>

#include "tssproperties.h"

struct tss_ftpm_context {
    uintptr_t commandBuffer;
    uint32_t written;
    uintptr_t responseBuffer;
    uint32_t read;
};


#define FTPM_IOC_MAGIC  0xa5

#define FTPM_IOC_RUN_COMMAND \
  _IOWR(FTPM_IOC_MAGIC, 0x01, struct tss_ftpm_context)


/* TSS_Dev_Open() opens the TPM device (through the device driver) */

static uint32_t TSS_FTPM_Dev_Open(TSS_CONTEXT *tssContext)
{
    uint32_t rc = 0;
    
	  tssContext->dev_fd = open(tssContext->tssDevice, O_RDWR);
	  if (tssContext->dev_fd < 0) {
	    printf("TSS_Dev_Open: Error opening %s\n", tssContext->tssDevice);
	    rc = TSS_RC_NO_CONNECTION;
	  }
    return rc;
}

TPM_RC TSS_FTPM_Transmit(TSS_CONTEXT *tssContext,
			uint8_t *responseBuffer, uint32_t *read,
			const uint8_t *commandBuffer, uint32_t written,
			const char *message)
{
    TPM_RC rc = 0;
    struct tss_ftpm_context cnx;

    /* open on first transmit */
    if (tssContext->tssFirstTransmit) {	
      if (rc == 0) {
          rc = TSS_FTPM_Dev_Open(tssContext);
      }
      if (rc == 0) {
          tssContext->tssFirstTransmit = FALSE;
      }
    }

    cnx.commandBuffer = (uintptr_t)commandBuffer;
    cnx.responseBuffer = (uintptr_t)responseBuffer;
    cnx.written = written;


    if (ioctl(tssContext->dev_fd, FTPM_IOC_RUN_COMMAND, &cnx)) {
      perror("[TSS] TSS_FTPM_Transmit(): ioctl error");
      return -1;
    }

    *read = cnx.read;

    return rc;
}