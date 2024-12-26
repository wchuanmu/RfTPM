/********************************************************************************/
/*										*/
/*		     	TPM2 Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2021.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsserror.h>
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#endif /* TPM_TSS_NOCRYPTO */
#include <ibmtss/tssutils.h>

#include "eventlib.h"
#include "efilib.h"

extern int tssUtilsVerbose;

/* NOTE: PFP is the TCG PC Client Platform Firmware Profile Specification
*/

#ifndef TPM_TSS_NOCRYPTO

/* function prototypes for event callback table */

typedef uint32_t (*TSS_Event2_CheckHash_t)(TCG_PCR_EVENT2 *event2,
					   const TCG_EfiSpecIDEvent *specIdEvent);

/* function callbacks */

static uint32_t TSS_Event2_Checkhash_Unused(TCG_PCR_EVENT2 *event2,
					    const TCG_EfiSpecIDEvent *specIdEvent);
static uint32_t TSS_Event2_Checkhash_EventHash(TCG_PCR_EVENT2 *event2,
					       const TCG_EfiSpecIDEvent *specIdEvent);
static uint32_t TSS_Event2_Checkhash_Success(TCG_PCR_EVENT2 *event2,
					     const TCG_EfiSpecIDEvent *specIdEvent);
static uint32_t TSS_Event2_Checkhash_VariableDataHash(TCG_PCR_EVENT2 *event2,
						      const TCG_EfiSpecIDEvent *specIdEvent);
static uint32_t TSS_Event2_Checkhash_VariableDataAuthority(TCG_PCR_EVENT2 *event2,
							   const TCG_EfiSpecIDEvent *specIdEvent);

#if 0	/* currently unused */
static uint32_t TSS_Event2_Checkhash_SignatureDataHash(TCG_PCR_EVENT2 *event2);
#endif

/* Tables to map eventType to hash check function callbacks.  NULL or missing entries return
   TSS_RC_NOT_IMPLEMENTED.

   The second check function, if not NULL, handles platforms that don't quite conform to the PTP.

   EV_EFI_VARIABLE_BOOT: Dell and Lenovo hash the variabledata, HP hashes the entire event.
*/

typedef struct {
    uint32_t 			eventType;
    TSS_Event2_CheckHash_t	checkHashFunction1;
    TSS_Event2_CheckHash_t	checkHashFunction2;
} TSS_EVENT2_CHECKHASH_TABLE;

const TSS_EVENT2_CHECKHASH_TABLE event2CheckHashTable [] =
    {
     {EV_PREBOOT_CERT,
      TSS_Event2_Checkhash_Unused,		/* reserved */
      NULL},
     {EV_POST_CODE,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_UNUSED,
      TSS_Event2_Checkhash_Unused,		/* deprecated */
      NULL},
     {EV_NO_ACTION,
      TSS_Event2_Checkhash_Success,		/* does not extend PCRs */
      NULL},
     {EV_SEPARATOR,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_ACTION,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_EVENT_TAG,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_S_CRTM_CONTENTS,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_S_CRTM_VERSION,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_CPU_MICROCODE,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_PLATFORM_CONFIG_FLAGS,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_TABLE_OF_DEVICES,
      TSS_Event2_Checkhash_Success,		/* FIXME cannot be verified due to UEFI bug */
      NULL},
     {EV_COMPACT_HASH,
      TSS_Event2_Checkhash_Success,		/* FIXME PFP ambiguous */
      NULL},
     {EV_IPL,
      TSS_Event2_Checkhash_Success,		/* FIXME PFP ambiguous */
      NULL},
     {EV_IPL_PARTITION_DATA,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_NONHOST_CODE,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_NONHOST_CONFIG,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_NONHOST_INFO,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_OMIT_BOOT_DEVICE_EVENTS,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_VARIABLE_DRIVER_CONFIG,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_EFI_VARIABLE_BOOT,
      TSS_Event2_Checkhash_VariableDataHash,	/* PCR is hash of variable data */
      TSS_Event2_Checkhash_EventHash},		/* HP hashes entire event */
     {EV_EFI_BOOT_SERVICES_APPLICATION,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_BOOT_SERVICES_DRIVER,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_RUNTIME_SERVICES_DRIVER,
      NULL,
      NULL},
     {EV_EFI_GPT_EVENT,
      TSS_Event2_Checkhash_EventHash,		/* guess, PTP unclear */
      NULL},
     {EV_EFI_ACTION,
      TSS_Event2_Checkhash_EventHash,
      NULL},
     {EV_EFI_PLATFORM_FIRMWARE_BLOB,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_HANDOFF_TABLES,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_PLATFORM_FIRMWARE_BLOB2,
      TSS_Event2_Checkhash_Success,		/* PCR does not contain hash of event */
      NULL},
     {EV_EFI_HANDOFF_TABLES2,
      TSS_Event2_Checkhash_Success,
      NULL},
     {EV_EFI_HCRTM_EVENT,
      NULL,
      NULL},
     {EV_EFI_VARIABLE_AUTHORITY,
      TSS_Event2_Checkhash_EventHash,			/* this is what vendors seem to do */
      TSS_Event2_Checkhash_VariableDataAuthority},	/* Supermicro quirk */
     {EV_EFI_SUPERMICRO_1,
      TSS_Event2_Checkhash_Success,		/* unknown event Supermicro quirk */
      NULL},
    };

static uint32_t TSS_Event2_Checkhash_GetTableIndex(size_t *index, uint32_t eventType);

/* TSS_Event2_Checkhash_GetTableIndex() searches the event type table for the event handlers.

   Returns TSS_RC_NOT_IMPLEMENTED if the event type is unknown.
*/

static uint32_t TSS_Event2_Checkhash_GetTableIndex(size_t *index, uint32_t eventType)
{
    for (*index = 0 ;
	 *index < sizeof(event2CheckHashTable) / sizeof(TSS_EVENT2_CHECKHASH_TABLE) ;
	 (*index)++) {
	if (event2CheckHashTable [*index].eventType == eventType) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/*
  Check Hash callbacks
*/

/* TSS_Event2_Checkhash_Unused() is used for events that are reserved, deprecated, or otherwise
   unexpected and not handled */

static uint32_t TSS_Event2_Checkhash_Unused(TCG_PCR_EVENT2 *event2,
					    const TCG_EfiSpecIDEvent *specIdEvent)
{
    event2 = event2;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;
    return TSS_RC_NOT_IMPLEMENTED;
}

/* TSS_Event2_Checkhash_Success() is used for events that do not extend PCRs.  An example is
   EV_NO_ACTION.

   Normally Checkhash would not be called for these events, but returning success may simplfy
   application code.
*/

static uint32_t TSS_Event2_Checkhash_Success(TCG_PCR_EVENT2 *event2,
					     const TCG_EfiSpecIDEvent *specIdEvent)
{
    event2 = event2;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;
    return 0;
}

static uint32_t TSS_Event2_Checkhash_EventHash(TCG_PCR_EVENT2 *event2,
					       const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    int irc;
    uint32_t count;
    TPML_DIGEST_VALUES *digestValues = &event2->digests;

    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    for (count = 0 ; (rc == 0) && (count < digestValues ->count) ; count++) {

	TPMT_HA *pcrDigest = &(digestValues->digests[count]);	/* value extended */
	TPMI_ALG_HASH hashAlg = pcrDigest->hashAlg;
	TPMT_HA eventDigest;				/* value from event */

	if (rc == 0) {
	    eventDigest.hashAlg = hashAlg;
	    rc = TSS_Hash_Generate(&eventDigest,
				   event2->eventSize, event2->event,
				   0, NULL);
	}
	if (rc == 0) {
	    uint32_t sizeInBytes = TSS_GetDigestSize(hashAlg);
#if 0
	    printf("TSS_Event2_Checkhash_EventHash: bytes to hash %u\n",
		   event2->eventSize);
	    printf("TSS_Event2_Checkhash_EventHash: first byte %02x\n", event2->event[0]);
	    printf("TSS_Event2_Checkhash_EventHash: last byte %02x\n",
		   event2->event[event2->eventSize-1]);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_EventHash: PCR",
					      (uint8_t *)&pcrDigest->digest, sizeInBytes);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_EventHash: event",
					      (uint8_t *)&eventDigest.digest, sizeInBytes);
#endif
	    irc = memcmp((uint8_t *)&pcrDigest->digest,
			 (uint8_t *)&eventDigest.digest,
			 sizeInBytes);
	    if (irc != 0) {
#if 0
		printf("TSS_Event2_Checkhash_EventHash: "
		       "ERROR: hash mismatch PCR %08x, event type %08x hash alg %08x\n",
		       event2->pcrIndex, event2->eventType, hashAlg);
#endif
		rc = TSS_RC_HASH;
	    }
	}
    }
    return rc;
}

/* TSS_Event2_Checkhash_VariableDataHash() events extend just the VariableData, not the entire
   event
*/

static uint32_t TSS_Event2_Checkhash_VariableDataHash(TCG_PCR_EVENT2 *event2,
						      const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    int irc;
    uint32_t count;
    TPML_DIGEST_VALUES *digestValues = &event2->digests;
    TSST_EFIData *efiData = NULL;
    uint8_t *VariableData;
    uint64_t VariableDataLength;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    /* Parse the event and get the VariableData */
    if (rc == 0) {
	rc = TSS_EFIData_Init(&efiData, event2->eventType, specIdEvent);
    }
    if (rc == 0) {
	rc = TSS_EFIData_ReadBuffer(efiData, event2->event, event2->eventSize,
				    event2->pcrIndex, specIdEvent);
    }
    /* get the VariableData and its length from the structure */
    if (rc == 0) {
	VariableData = efiData->efiData.uefiVariableData.VariableData;
	VariableDataLength = efiData->efiData.uefiVariableData.VariableDataLength;
    }
    for (count = 0 ; (rc == 0) && (count < digestValues ->count) ; count++) {

	TPMT_HA *pcrDigest = &(digestValues->digests[count]);	/* value extended */
	TPMI_ALG_HASH hashAlg = pcrDigest->hashAlg;
	TPMT_HA variableDataDigest;				/* value from event */

	if (rc == 0) {
	    variableDataDigest.hashAlg = hashAlg;
	    rc = TSS_Hash_Generate(&variableDataDigest,
				   (uint32_t)VariableDataLength, VariableData,
				   0, NULL);
	}
	if (rc == 0) {
	    uint32_t sizeInBytes = TSS_GetDigestSize(hashAlg);
#if 0
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_VariableDataHash: PCR",
					      (uint8_t *)&pcrDigest->digest, sizeInBytes);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_VariableDataHash: VariableData",
					      (uint8_t *)&variableDataDigest.digest, sizeInBytes);
#endif
	    irc = memcmp((uint8_t *)&pcrDigest->digest,
			 (uint8_t *)&variableDataDigest.digest,
			 sizeInBytes);
	    if (irc != 0) {
#if 0
		printf("TSS_Event2_Checkhash_VariableDataHash:\n"
		       "\tERROR: hash mismatch PCR %08x, event type %08x hash alg %08x\n",
		       event2->pcrIndex, event2->eventType, hashAlg);
#endif
		rc = TSS_RC_HASH;
	    }
	}
    }
    TSS_EFIData_Free(efiData, specIdEvent);
    return rc;
}

/* TSS_Event2_Checkhash_VariableDataAuthority() handles a Supermicro EV_EFI_VARIABLE_AUTHORITY event
   that has an off by one error.  The last byte of the event is not hashed.
*/

static uint32_t TSS_Event2_Checkhash_VariableDataAuthority(TCG_PCR_EVENT2 *event2,
							   const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    int irc;
    uint32_t count;
    TPML_DIGEST_VALUES *digestValues = &event2->digests;
    uint32_t offByOne = 1;	/* Supermicro bug */
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    for (count = 0 ; (rc == 0) && (count < digestValues ->count) ; count++) {

	TPMT_HA *pcrDigest = &(digestValues->digests[count]);	/* value extended */
	TPMI_ALG_HASH hashAlg = pcrDigest->hashAlg;
	TPMT_HA eventDigest;				/* value from event */

	if (rc == 0) {
	    eventDigest.hashAlg = hashAlg;
	    rc = TSS_Hash_Generate(&eventDigest,
				   (uint32_t)event2->eventSize-offByOne, event2->event,
				   0, NULL);
	}
	if (rc == 0) {
	    uint32_t sizeInBytes = TSS_GetDigestSize(hashAlg);
#if 0
	    printf("TSS_Event2_Checkhash_VariableDataAuthority: bytes to hash %u\n",
		   (uint32_t)event2->eventSize-offByOne);
	    printf("TSS_Event2_Checkhash_VariableDataAuthority: first byte %02x\n",
		   event2->event[0]);
	    printf("TSS_Event2_Checkhash_VariableDataAuthority: last byte %02x\n",
		   event2->event[event2->eventSize-1-offByOne]);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_VariableDataAuthority: PCR",
					      (uint8_t *)&pcrDigest->digest, sizeInBytes);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_VariableDataAuthority: event",
					      (uint8_t *)&eventDigest.digest, sizeInBytes);
#endif
	    irc = memcmp((uint8_t *)&pcrDigest->digest,
			 (uint8_t *)&eventDigest.digest,
			 sizeInBytes);
	    if (irc != 0) {
		printf("TSS_Event2_Checkhash_VariableDataAuthority: "
		       "ERROR: hash mismatch PCR %08x, event type %08x hash alg %08x\n",
		       event2->pcrIndex, event2->eventType, hashAlg);
		rc = TSS_RC_HASH;
	    }
	}
    }
    return rc;
}

#if 0	/* Not used, OEMs seem to not follow the PFP */

/* TSS_Event2_Checkhash_SignatureDataHash() events extend just the UEFI signature data, not the
   entire event.

   This function (untested) agrees with the PFP, although OEMs seem to do it differently.

*/

static uint32_t TSS_Event2_Checkhash_SignatureDataHash(TCG_PCR_EVENT2 *event2,
						       const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    int irc;
    uint32_t count;
    TPML_DIGEST_VALUES *digestValues = &event2->digests;
    TSST_EFIData *efiData = NULL;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData;
    uint8_t *hashData;
    uint64_t hashDataLength;
    uint32_t offset;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    /* Parse the event and get the VariableData */
    if (rc == 0) {
	rc = TSS_EFIData_Init(&efiData, event2->eventType);
    }
    if (rc == 0) {
	rc = TSS_EFIData_ReadBuffer(efiData, event2->event, event2->eventSize, event2->pcrIndex);
    }
    /* get the hashed data and its length from the structure */
    if (rc == 0) {
	uefiVariableData = &efiData->efiData.uefiVariableData;
	/* DB has a signature length */
	if (uefiVariableData->variableDataTag == VAR_DB) {
	    /* offset into event is variable GUID + 2 uint64_t lengths + UC16 "DB" */
	    offset = sizeof(efi_guid_t) + sizeof(uint64_t) + sizeof(uint64_t) + 4;
	}
	else if (uefiVariableData->variableDataTag == VAR_SHIM) {
	    /* offset into event is variable GUID + 2 uint64_t lengths + UC16 "Shim" */
	    offset = sizeof(efi_guid_t) + sizeof(uint64_t) + sizeof(uint64_t) + 8;
	}
	else if (uefiVariableData->variableDataTag == VAR_MOKLIST) {
	    /* offset into event is variable GUID + 2 uint64_t lengths + UC16 "Moklist" */
	    offset = sizeof(efi_guid_t) + sizeof(uint64_t) + sizeof(uint64_t) + 14;
	}
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
	hashData = event2->event + offset;
	hashDataLength = event2->eventSize - offset;
    }
   for (count = 0 ; (rc == 0) && (count < digestValues ->count) ; count++) {

	TPMT_HA *pcrDigest = &(digestValues->digests[count]);	/* value extended */
	TPMI_ALG_HASH hashAlg = pcrDigest->hashAlg;
	TPMT_HA signatureDataDigest;				/* value from event */

	if (rc == 0) {
	    signatureDataDigest.hashAlg = hashAlg;
	    rc = TSS_Hash_Generate(&signatureDataDigest,
				   (uint32_t)hashDataLength, hashData,
				   0, NULL);
	}
	if (rc == 0) {
	    uint32_t sizeInBytes = TSS_GetDigestSize(hashAlg);
#if 0
	    printf("TSS_Event2_Checkhash_SignatureDataHash: bytes to hash %u\n",
		   (uint32_t)hashDataLength);
	    printf("TSS_Event2_Checkhash_SignatureDataHash: first byte %02x\n", hashData[0]);
	    printf("TSS_Event2_Checkhash_SignatureDataHash: last byte %02x\n",
		   hashData[hashDataLength-1]);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_SignatureDataHash: PCR",
					      (uint8_t *)&pcrDigest->digest, sizeInBytes);
	    if (tssUtilsVerbose) TSS_PrintAll("TSS_Event2_Checkhash_SignatureDataHash: event",
					      (uint8_t *)&signatureDataDigest.digest, sizeInBytes);
#endif
	    irc = memcmp((uint8_t *)&pcrDigest->digest,
			 (uint8_t *)&signatureDataDigest.digest,
			 sizeInBytes);
	    if (irc != 0) {
		printf("TSS_Event2_Checkhash_SignatureDataHash: "
		       "ERROR: hash mismatch PCR %08x, event type %08x hash alg %08x\n",
		       event2->pcrIndex, event2->eventType, hashAlg);
		rc = TSS_RC_HASH;
	    }
	}
    }
    TSS_EFIData_Free(efiData);
    return rc;
}

#endif	/* function currently unused */

/* TSS_EVENT2_Line_CheckHash() checks the event against the PCR hash.

   A not implemented check returns TSS_RC_NOT_IMPLEMENTED.
   A NULL entry in the table primary method returns TSS_RC_NOT_IMPLEMENTED.
   A NULL entry in the table second method returns the error from the primary method.
*/

TPM_RC TSS_EVENT2_Line_CheckHash(TCG_PCR_EVENT2 *event,
				 const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;

    /* if the eventType is not supported, returns TSS_RC_NOT_IMPLEMENTED */
    if (rc == 0) {
	rc = TSS_Event2_Checkhash_GetTableIndex(&index, event->eventType);
    }
    if (rc == 0) {
	/* if there is a primary method */
	if (event2CheckHashTable[index].checkHashFunction1 != NULL) {
	    /* try the primary method */
	    rc = event2CheckHashTable[index].checkHashFunction1(event, specIdEvent);
	    /* if the primary method failed, try the second, alternate */
	    if (rc != 0) {
		/* if there is a second method */
		if (event2CheckHashTable[index].checkHashFunction2 != NULL) {
		    /* try the second method */
		    rc = event2CheckHashTable[index].checkHashFunction2(event, specIdEvent);
		}
		/* else use the rc from the primary method */
	    }
	}
	/* no checkHashFunction1, not implemented */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    if (rc != 0) {
	printf("TSS_EVENT2_Line_CheckHash: Error: rc %08x\n", rc);
    }
    return rc;
}

#endif /* TPM_TSS_NOCRYPTO */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
static uint16_t Uint16_Convert(uint16_t in);
#endif /* TPM_TPM20 */
static uint32_t Uint32_Convert(uint32_t in);
#endif /* TPM_TSS_NOFILE */
static void TSS_EVENT_EventType_Trace(uint32_t eventType);
static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size);
static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize);
#ifdef TPM_TPM20
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target,
						   BYTE **buffer,
						   uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer,
					uint32_t *size, BOOL allowNull);
static TPM_RC TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target,
					      BYTE **buffer, uint32_t *size,
					      BOOL allowNull);
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
						 uint16_t *written, BYTE **buffer,
						 uint32_t *size);
static TPM_RC TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target,
					   BYTE **buffer, uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
				      BYTE **buffer, uint32_t *size);
#endif /* TPM_TPM20 */

/* TSS_EVENT_Line_Read() reads a TPM 1.2 SHA-1 event line from a binary file inFile.

 */

#ifndef TPM_TSS_NOFILE
int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			int *endOfFile,
			FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long) readSize);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the digest */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->digest),
			 sizeof(((TCG_PCR_EVENT *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read digest, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event data size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventDataSize),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventDataSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event data size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventDataSize = Uint32_Convert(event->eventDataSize);
    }
    /* bounds check the event data length */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventDataSize > sizeof(((TCG_PCR_EVENT *)NULL)->event)) {
	    printf("TSS_EVENT_Line_Read: Error, event data length too big: %u\n",
		   event->eventDataSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventDataSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT_Line_Marshal() marshals a TCG_PCR_EVENT structure */

TPM_RC TSS_EVENT_Line_Marshal(TCG_PCR_EVENT *source,
			      uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventDataSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->event, source->eventDataSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure

 */

TPM_RC TSS_EVENT_Line_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT_Line_LE_Unmarshal() Unmarshal LE buffer into a target TCG_PCR_EVENT
*/
TPM_RC TSS_EVENT_Line_LE_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
/* TSS_EVENT_PCR_Extend() extends PCR digest with the digest from the TCG_PCR_EVENT event log
   entry.
*/

TPM_RC TSS_EVENT_PCR_Extend(TPMT_HA pcrs[IMPLEMENTATION_PCR],
			    TCG_PCR_EVENT *event)
{
    TPM_RC 		rc = 0;
    
    /* validate PCR number */
    if (rc == 0) {
	if (event->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: TSS_EVENT_PCR_Extend: PCR number %u out of range\n", event->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* process each event hash algorithm */
    if (rc == 0) {
	pcrs[event->pcrIndex].hashAlg = TPM_ALG_SHA1;	/* should already be initialized */
	if (rc == 0) {
	    rc = TSS_Hash_Generate(&pcrs[event->pcrIndex],
				   SHA1_DIGEST_SIZE, (uint8_t *)&pcrs[event->pcrIndex].digest,
				   SHA1_DIGEST_SIZE, &event->digest,
				   0, NULL);
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOCRYPTO */

void TSS_EVENT_Line_Trace(TCG_PCR_EVENT *event)
{
    printf("TSS_EVENT_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    TSS_PrintAll("TSS_EVENT_Line_Trace: PCR",
		 event->digest, sizeof(((TCG_PCR_EVENT *)NULL)->digest));
    TSS_PrintAll("TSS_EVENT_Line_Trace: event",
		 event->event, event->eventDataSize);
    if (event->eventType == EV_IPL) {	/* this event appears to be printable strings */
	printf(" %.*s\n", event->eventDataSize, event->event);
    }
    return;
}

/* TSS_SpecIdEvent_Unmarshal() unmarshals the TCG_EfiSpecIDEvent structure.

   The size and buffer are not moved, since this is the only structure in the event.
*/

TPM_RC TSS_SpecIdEvent_Unmarshal(TCG_EfiSpecIDEvent *specIdEvent,
				 uint32_t eventSize,
				 uint8_t *event)
{
    TPM_RC	rc = 0;
    uint32_t	size = eventSize;	/* copy, because size and buffer are not moved */
    uint8_t	*buffer = event;
    uint32_t 	i;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->signature, sizeof(specIdEvent->signature),
			     &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&(specIdEvent->platformClass), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMinor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMajor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specErrata), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->uintnSize), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&(specIdEvent->numberOfAlgorithms), &buffer, &size);
    }
    for (i = 0 ; (rc == 0) && (i < specIdEvent->numberOfAlgorithms) ; i++) {
	rc = TSS_SpecIdEventAlgorithmSize_Unmarshal(&(specIdEvent->digestSizes[i]),
						    &buffer, &size);
    }	    
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->vendorInfoSize), &buffer, &size);
    }
#if 0	/* NOTE: Can never fail because vendorInfoSize is uint8_t and vendorInfo is 0xff bytes */
    if (rc == 0) {
	if (specIdEvent->vendorInfoSize > sizeof(specIdEvent->vendorInfo)) {
	    rc = TPM_RC_SIZE;
	}
    }    
#endif
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->vendorInfo, specIdEvent->vendorInfoSize,
			     &buffer, &size);
    }
    return rc;
}

/* TSS_SpecIdEventAlgorithmSize_Unmarshal() unmarshals the TCG_EfiSpecIdEventAlgorithmSize
   structure */

static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size)
{
    TPM_RC	rc = 0;

    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&(algSize->algorithmId), buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&(algSize->digestSize), buffer, size);
    } 
    if (rc == 0) {
	uint16_t mappedDigestSize = TSS_GetDigestSize(algSize->algorithmId);
	if (mappedDigestSize != 0) {
	    if (mappedDigestSize != algSize->digestSize) {
		printf("TSS_SpecIdEventAlgorithmSize_Unmarshal: "
		       "Error, inconsistent digest size, algorithm %04x size %u\n",
		       algSize->algorithmId, algSize->digestSize);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
    }
    return rc;
}

void TSS_SpecIdEvent_Trace(TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t 	i;

    /* normal case */
    if (specIdEvent->signature[15] == '\0')  {
	printf("TSS_SpecIdEvent_Trace: signature: %s\n", specIdEvent->signature);
    }
    /* error case */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: signature",
		     specIdEvent->signature, sizeof(specIdEvent->signature));
    }
    printf("TSS_SpecIdEvent_Trace: platformClass %08x\n", specIdEvent->platformClass);
    printf("TSS_SpecIdEvent_Trace: specVersionMinor %02x\n", specIdEvent->specVersionMinor);
    printf("TSS_SpecIdEvent_Trace: specVersionMajor %02x\n", specIdEvent->specVersionMajor);
    printf("TSS_SpecIdEvent_Trace: specErrata %02x\n", specIdEvent->specErrata);
    printf("TSS_SpecIdEvent_Trace: uintnSize %02x\n", specIdEvent->uintnSize);
    printf("TSS_SpecIdEvent_Trace: numberOfAlgorithms %u\n", specIdEvent->numberOfAlgorithms);
    for (i = 0 ; (i < specIdEvent->numberOfAlgorithms) ; i++) {
	TSS_SpecIdEventAlgorithmSize_Trace(&(specIdEvent->digestSizes[i]));
    }
    /* try for a printable string */
    if (specIdEvent->vendorInfoSize > 0) {
	if (specIdEvent->vendorInfo[specIdEvent->vendorInfoSize-1] == '\0')  {
	    printf("TSS_SpecIdEvent_Trace: vendorInfo: %s\n", specIdEvent->vendorInfo);
	}
    }
    /* if not, trace the bytes */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: vendorInfo",
		     specIdEvent->vendorInfo, specIdEvent->vendorInfoSize);
    }
    return;
}

static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize)
{
    printf("TSS_SpecIdEventAlgorithmSize_Trace: algorithmId %04x\n", algSize->algorithmId);
    printf("TSS_SpecIdEventAlgorithmSize_Trace: digestSize %u\n", algSize->digestSize);
    return;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOFILE

/* TSS_EVENT2_Line_Read() reads a TPM2 event line from a binary file inFile.

*/

int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event,
			 int *endOfFile,
			 FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    uint32_t maxCount; 
    uint32_t count;

    *endOfFile = FALSE;
    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT2_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the TPML_DIGEST_VALUES count */
    if (!*endOfFile && (rc == 0)) {
	maxCount = sizeof((TPML_DIGEST_VALUES *)NULL)->digests / sizeof(TPMT_HA);
	readSize = fread(&(event->digests.count),
			 sizeof(((TPML_DIGEST_VALUES *)NULL)->count), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read digest count, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->digests.count = Uint32_Convert(event->digests.count);
    }
    /* range check the digest count */
    if (!*endOfFile && (rc == 0)) {
	if (event->digests.count > maxCount) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count %u is greater than structure %u\n",
		   event->digests.count, maxCount);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (event->digests.count == 0) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count is zero\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read all the TPMT_HA, loop through all the digest algorithms */
    for (count = 0 ; !*endOfFile && (count < event->digests.count) ; count++) {
	uint16_t digestSize;
	/* read the digest algorithm */
	if (rc == 0) {
	    readSize = fread(&(event->digests.digests[count].hashAlg),
			     sizeof((TPMT_HA *)NULL)->hashAlg, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: "
		       "Error, could not read digest algorithm, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* do the endian conversion of the hash algorithm from stream to uint16_t */
	if (rc == 0) {
	    event->digests.digests[count].hashAlg =
		Uint16_Convert(event->digests.digests[count].hashAlg);
	}
	/* map from the digest algorithm to the digest length */
	if (rc == 0) {
	    digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	    if (digestSize == 0) {
		printf("TSS_EVENT2_Line_Read: Error, unknown digest algorithm %04x*\n",
		       event->digests.digests[count].hashAlg);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* read the digest */
	if (rc == 0) {
	    readSize = fread((uint8_t *)&(event->digests.digests[count].digest),
			     digestSize, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: Error, could not read digest, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the event size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventSize),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventSize = Uint32_Convert(event->eventSize);
    }
    /* bounds check the event size */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventSize > sizeof(((TCG_PCR_EVENT2 *)NULL)->event)) {
	    printf("TSS_EVENT2_Line_Read: Error, event size too big: %u\n",
		   event->eventSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (event->eventSize > 0) && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT2 *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT2_Line_Marshal() marshals a TCG_PCR_EVENT2 structure */

TPM_RC TSS_EVENT2_Line_Marshal(TCG_PCR_EVENT2 *source,
			       uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Marshal() Marshals a TSS_EVENT2 structure from HBO into LE
 * and saves to buffer.
 */
TPM_RC TSS_EVENT2_Line_LE_Marshal(TCG_PCR_EVENT2 *source, uint16_t *written,
				  uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT2_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure */


TPM_RC TSS_EVENT2_Line_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Unmarshal() Unmarshals an LE eventlog buffer and save to
 * the target TCG_PCR_EVENT2
 */
TPM_RC TSS_EVENT2_Line_LE_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO

/* TSS_EVENT2_PCR_Extend() extends PCR digests with the digest from the TCG_PCR_EVENT2 event log
   entry.

   It ignores EV_NO_ACTION events except for StartupLocality.  StartupLocality resets the simulated
   PCR 0 to the locality.

   It assumes that the hash algorithm for the entire HASH_COUNT array is initialized.  Use
   TPM_ALG_NULL for unused banks.
*/

TPM_RC TSS_EVENT2_PCR_Extend(TPMT_HA pcrs[HASH_COUNT][IMPLEMENTATION_PCR],
			     TCG_PCR_EVENT2 *event2)
{
    TPM_RC 		rc = 0;
    uint32_t 		i;		/* iterator though hash algorithms */
    uint32_t 		bankNum = 0;	/* iterator though PCR hash banks */
    uint16_t 		digestSize;

    /* validate event count */
    if (rc == 0) {
	uint32_t maxCount = sizeof(((TPML_DIGEST_VALUES *)NULL)->digests) / sizeof(TPMT_HA);
	if (event2->digests.count > maxCount) {
	    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR count %u out of range, max %u\n",
		   event2->digests.count, maxCount);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	} 
    }
    /*
      This logic handles EV_NO_ACTION -> StartupLocality.  If that event is encountered, set PCR 0
      to the locality value before the extend.

      This logic assumes that pcrs[] has been initialized to all zero.  The caller does this as part
      of the simulated (event log replay) PCR calculation.

      An error case is this event when PCR 0 is not zero.  Ignore it here since that would just be
      an attestation client DoS'ing itself.  I.e., the attacker can reset PCR 0 in this simulation
      calculation, but cannot reset the TPM PCR 0.

      The event is a fixed value, " StartupLocality" plus a byte locality (e.g., for locality
      3)

      53 74 61 72 74 75 70 4c 6f 63 61 6c 69 74 79 00
      03 

    */
    if (rc == 0) {
	if (event2->eventType == EV_NO_ACTION) {
	    if ((event2->pcrIndex == 0) &&
		(event2->eventSize == (sizeof("StartupLocality") + 1)) &&
		(memcmp(event2->event, "StartupLocality", sizeof("StartupLocality")) == 0)) {

		uint8_t locality = event2->event[sizeof("StartupLocality")];
		for (i = 0; (rc == 0) && (i < event2->digests.count) ; i++) {
		    digestSize = TSS_GetDigestSize(pcrs[i][0].hashAlg);
		    pcrs[i][0].digest.tssmax[digestSize-1] = locality;
		}
	    }
	    /* no 'else', other EV_NO_ACTION events are ignored */
	}
	/* not EV_NO_ACTION */
	else {
	    /* Range check event PCR number.  Do not do this test for EV_NO_ACTION, which can have
	       non-standard PCR values like 0xffffffff */
	    if (rc == 0) {
		if (event2->pcrIndex >= IMPLEMENTATION_PCR) {
		    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR number %u out of range\n",
			   event2->pcrIndex);
		    rc = TSS_RC_BAD_PROPERTY_VALUE;
		}
	    }
	    /* process each event hash algorithm */
	    for (i = 0; (rc == 0) && (i < event2->digests.count) ; i++) {
		/* find the simulated PCR bank matching the event at count i */
		for (bankNum = 0 ; (rc == 0) && (bankNum < HASH_COUNT) ; bankNum++) {
		    if (pcrs[bankNum][0].hashAlg == event2->digests.digests[i].hashAlg) {

			if (rc == 0) {
			    digestSize = TSS_GetDigestSize(event2->digests.digests[i].hashAlg);
			    if (digestSize == 0) {
				printf("ERROR: TSS_EVENT2_PCR_Extend: hash algorithm %04hx unknown\n",
				       event2->digests.digests[i].hashAlg);
				rc = TSS_RC_BAD_HASH_ALGORITHM;
			    }
			}
			if (rc == 0) {
			    rc = TSS_Hash_Generate(&pcrs[bankNum][event2->pcrIndex],
						   digestSize,
						   (uint8_t *)&pcrs[bankNum][event2->pcrIndex].digest,
						   digestSize,
						   &event2->digests.digests[i].digest,
						   0, NULL);
			}
			break;	/* stop scanning pcrs[] banks on match */
		    }
		}
	    }
	}
    }
#if 0	/* for debug, trace the PCR calculation after each extend */
    if (tssUtilsVerbose) {
	/* process each event hash algorithm */
	for (i = 0; (rc == 0) && (i < event2->digests.count) ; i++) {
	    digestSize = TSS_GetDigestSize(event2->digests.digests[i].hashAlg);
	    TSS_PrintAll("TSS_EVENT2_PCR_Extend:",
			 (uint8_t *)&pcrs[i][event2->pcrIndex].digest, digestSize);
	}
    }
#endif
    return rc;
}

#endif /* TPM_TSS_NOCRYPTO */
#endif	/* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* Uint16_Convert() converts a little endian uint16_t (from an input stream) to host byte order
 */

static uint16_t Uint16_Convert(uint16_t in)
{
    uint16_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8);
    return out;
}

#endif

/* Uint32_Convert() converts a little endian uint32_t (from an input stream) to host byte order
 */

static uint32_t Uint32_Convert(uint32_t in)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;

    /* little endian input */
    out = ((((uint32_t)inb[0]) <<  0) |
	   (((uint32_t)inb[1]) <<  8) |
	   (((uint32_t)inb[2]) << 16) |
	   (((uint32_t)inb[3]) << 24));
    return out;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_UINT16LE_Unmarshal() unmarshals a little endian 2-byte array from buffer into a HBO uint16_t */

TPM_RC TSS_UINT16LE_Unmarshal(uint16_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint16_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint16_t)((*buffer)[0]) <<  0) |
	      ((uint16_t)((*buffer)[1]) <<  8);
    *buffer += sizeof(uint16_t);
    *size -= sizeof(uint16_t);
    return TPM_RC_SUCCESS;
}

/* TSS_UINT32LE_Unmarshal() unmarshals a little endian 4-byte array from buffer into a HBO uint32_t */

TPM_RC TSS_UINT32LE_Unmarshal(uint32_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint32_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint32_t)((*buffer)[0]) <<  0) |
	      ((uint32_t)((*buffer)[1]) <<  8) |
	      ((uint32_t)((*buffer)[2]) << 16) |
	      ((uint32_t)((*buffer)[3]) << 24);
    *buffer += sizeof(uint32_t);
    *size -= sizeof(uint32_t);
    return TPM_RC_SUCCESS;
}

/* TSS_UINT64LE_Unmarshal() unmarshals a little endian 8-byte array from buffer into a HBO uint64_t */

TPM_RC TSS_UINT64LE_Unmarshal(uint64_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint64_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint64_t)((*buffer)[0]) <<  0) |
	      ((uint64_t)((*buffer)[1]) <<  8) |
	      ((uint64_t)((*buffer)[2]) << 16) |
	      ((uint64_t)((*buffer)[3]) << 24) |
	      ((uint64_t)((*buffer)[4]) << 32) |
	      ((uint64_t)((*buffer)[5]) << 40) |
	      ((uint64_t)((*buffer)[6]) << 48) |
	      ((uint64_t)((*buffer)[7]) << 56);
    *buffer += sizeof(uint64_t);
    *size -= sizeof(uint64_t);
    return TPM_RC_SUCCESS;
}

/* TSS_EVENT2_Line_Trace() is a deprecated function that cannot handle different PC Client PFP
   specifications.
*/

void TSS_EVENT2_Line_Trace(TCG_PCR_EVENT2 *event)
{
    TSS_EVENT2_Line_Trace2(event, NULL);
    return;
}

/* TSS_EVENT2_Line_Trace2() is recommended.  It adds the TCG_EfiSpecIDEvent parameter, which can
   eventually handle updates to the PC Client PFP specifications.

   A NULL TCG_EfiSpecIDEvent is permissible as a default to the TSS_EVENT2_Line_Trace() behavior.
*/

void TSS_EVENT2_Line_Trace2(TCG_PCR_EVENT2 *event,
			    const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    uint32_t count;
    uint16_t digestSize;
    TSST_EFIData *efiData = NULL;
    printf("TSS_EVENT2_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    printf("TSS_EVENT2_Line_Trace: digest count %u\n", event->digests.count);
    for (count = 0 ; count < event->digests.count ; count++) {
	printf("TSS_EVENT2_Line_Trace: digest %u algorithm %04x\n",
	       count, event->digests.digests[count].hashAlg);
	digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	TSS_PrintAll("TSS_EVENT2_Line_Trace: PCR",
		     (uint8_t *)&event->digests.digests[count].digest, digestSize);
    }
    TSS_PrintAll("TSS_EVENT2_Line_Trace: event",
		 event->event, event->eventSize);
    /* trace down into the EFI event */
    if (rc == 0) {
	rc = TSS_EFIData_Init(&efiData, event->eventType, specIdEvent);
    }
    if (rc == 0) {
	rc = TSS_EFIData_ReadBuffer(efiData, event->event, event->eventSize,
				    event->pcrIndex, specIdEvent);
    }
    if (rc == 0) {
	TSS_EFIData_Trace(efiData, specIdEvent);
    }
    TSS_EFIData_Free(efiData, specIdEvent);
    return;
}

/* tables to map eventType to text */

typedef struct {
    uint32_t eventType;
    const char *text;
} EVENT_TYPE_TABLE;

const EVENT_TYPE_TABLE eventTypeTable [] = {
    {EV_PREBOOT_CERT, "EV_PREBOOT_CERT"},
    {EV_POST_CODE, "EV_POST_CODE"},
    {EV_UNUSED, "EV_UNUSED"},
    {EV_NO_ACTION, "EV_NO_ACTION"},
    {EV_SEPARATOR, "EV_SEPARATOR"},
    {EV_ACTION, "EV_ACTION"},
    {EV_EVENT_TAG, "EV_EVENT_TAG"},
    {EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS"},
    {EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION"},
    {EV_CPU_MICROCODE, "EV_CPU_MICROCODE"},
    {EV_PLATFORM_CONFIG_FLAGS, "EV_PLATFORM_CONFIG_FLAGS"},
    {EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES"},
    {EV_COMPACT_HASH, "EV_COMPACT_HASH"},
    {EV_IPL, "EV_IPL"},
    {EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA"},
    {EV_NONHOST_CODE, "EV_NONHOST_CODE"},
    {EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG"},
    {EV_NONHOST_INFO, "EV_NONHOST_INFO"},
    {EV_OMIT_BOOT_DEVICE_EVENTS, "EV_OMIT_BOOT_DEVICE_EVENTS"},
    {EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE"},
    {EV_EFI_VARIABLE_DRIVER_CONFIG, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
    {EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT"},
    {EV_EFI_BOOT_SERVICES_APPLICATION, "EV_EFI_BOOT_SERVICES_APPLICATION"},
    {EV_EFI_BOOT_SERVICES_DRIVER, "EV_EFI_BOOT_SERVICES_DRIVER"},
    {EV_EFI_RUNTIME_SERVICES_DRIVER, "EV_EFI_RUNTIME_SERVICES_DRIVER"},
    {EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT"},
    {EV_EFI_ACTION, "EV_EFI_ACTION"},
    {EV_EFI_PLATFORM_FIRMWARE_BLOB, "EV_EFI_PLATFORM_FIRMWARE_BLOB"},
    {EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES"},
    {EV_EFI_PLATFORM_FIRMWARE_BLOB2, "EV_EFI_PLATFORM_FIRMWARE_BLOB2"},
    {EV_EFI_HANDOFF_TABLES2, "EV_EFI_HANDOFF_TABLES2"},
    {EV_EFI_HCRTM_EVENT, "EV_EFI_HCRTM_EVENT"},
    {EV_EFI_VARIABLE_AUTHORITY, "EV_EFI_VARIABLE_AUTHORITY"},
    {EV_EFI_SUPERMICRO_1, "EV_EFI_SUPERMICRO_1"}
};

static void TSS_EVENT_EventType_Trace(uint32_t eventType)
{
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    printf("TSS_EVENT_EventType_Trace: %08x %s\n",
		   eventTypeTable[i].eventType, eventTypeTable[i].text);
	    return;
	}
    }
    printf("TSS_EVENT_EventType_Trace: %08x Unknown\n", eventType);
    return;
}

const char *TSS_EVENT_EventTypeToString(uint32_t eventType)
{
    const char *crc = NULL;
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    crc = eventTypeTable[i].text;
	}
    }
    if (crc == NULL) {
	crc = "Unknown event type";
    }
    return crc;
}

#ifdef TPM_TPM20

/*
 * TSS_TPML_DIGEST_VALUES_LE_Unmarshalu() Unmarshals TPML_DIGEST_VALUES struct
 * from a LE buffer into HBO data structure. This is similar to
 * TSS_TPML_DIGEST_VALUES_Unmarshalu but it unrmarshals TPML_DIGEST_VALUES's
 * count  and the digests array members from LE instead of HBO.
 */

static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32LE_Unmarshal(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > HASH_COUNT) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMT_HA_LE_Unmarshalu(&target->digests[i], buffer, size, NO);
    }
    return rc;
}

/*
 * TSS_TPMT_HA_LE_Unmarshalu() Unmarshals a TPMT_HA data from LE to HBO. This is
 * similar to TSS_TPMT_HA_Unmarshalu but differs specificaly for unmarshalling
 * hashAlg member from LE instead of from HBO.
 */
static TPM_RC
TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_LE_Unmarshalu(&target->hashAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_HA_Unmarshalu(&target->digest, buffer, size, target->hashAlg);
    }
    return rc;
}

/*
 * TSS_TPMI_ALG_HASH_LE_Unmarshalu() Unmarshals TPMI_ALG_HASH from a LE buffer
 * into HBO data structure. This is similar to TSS_TPMI_ALG_HASH_Unmarshalu but
 * unmarshals TPMI_ALG_HASH from LE instead of HBO.
 */
static TPM_RC
TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_LE_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/*
 * TSS_TPM_ALG_ID_LE_Unmarshalu() Unrmarshals TPM_ALG_ID from LE buffer. This is
 * simlar to TSS_TPM_ALG_ID_Unmarshalu but unmarshals from LE instead of HBO.
 */
static TPM_RC
TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target, BYTE **buffer,
                                 uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16LE_Unmarshal(target, buffer, size);
    }
    return rc;
}

/* TSS_TPML_DIGEST_VALUES_LE_Marshalu() Similar to TSS_TPML_DIGEST_VALUES_Marshalu
 * for TSS EVENT2 this marshals count to buffer in LE endianess.
 */
static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
                                       uint16_t *written, BYTE **buffer,
                                       uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMT_HA_LE_Marshalu(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* TSS_TPMT_HA_LE_Marshalu() Similar to TSS_TPMT_HA_Marshalu for TSS EVENT2,
 * this saves hashAlg attr as little endian into buffer.
 */
static TPM_RC
TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
			BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16LE_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_HA_Marshalu(&source->digest, written, buffer, size,
                                  source->hashAlg);
    }
    return rc;
}

#endif /* TPM_TPM20 */

/*
 * TSS_UINT32LE_Marshal() Marshals uint32_t from HBO into LE in the given buffer.
 */
TPM_RC
TSS_UINT32LE_Marshal(const UINT32 *source, uint16_t *written, BYTE **buffer,
                 uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint32_t))) {
            (*buffer)[0] = (BYTE)((*source >> 0) &  0xff);
            (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);
            (*buffer)[2] = (BYTE)((*source >> 16) & 0xff);
            (*buffer)[3] = (BYTE)((*source >> 24) & 0xff);

            *buffer += sizeof(uint32_t);
            if (size != NULL) {
                *size -= sizeof(uint32_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint32_t);
    return rc;
}

/*
 * UINT16LE_Marshal() Marshals uint16_t from HBO into LE in the given buffer.
 */

TPM_RC
TSS_UINT16LE_Marshalu(const UINT16 *source, uint16_t *written, BYTE **buffer,
                      uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint16_t))) {
	    (*buffer)[0] = (BYTE)((*source >> 0) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);

            *buffer += sizeof(uint16_t);

            if (size != NULL) {
                *size -= sizeof(uint16_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint16_t);
    return rc;
}
