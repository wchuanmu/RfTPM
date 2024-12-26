/********************************************************************************/
/*										*/
/*		      Extend an IMA measurement list into PCRs			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2014 - 2023.					*/
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

/* imaextend is test/demo code.  It parses a TPM 1.2 IMA event log file and extends the measurements
   into TPM PCRs or simulated PCRs.  This simulates the actions that would be performed by the Linux
   kernel IMA in a hardware platform.

   To test incremental attestations, the caller can optionally specify a beginning event number and
   ending event number.

   To test a platform without a TPM or TPM device driver, but where IMA is creating an event log,
   the caller can optionally specify a sleep time.  The program will then incrementally extend after
   each sleep.

   Two IMA log types are supported:

   Type 1: For an older kernel that zero extends SHA-256 PCR

   sha1 bank: extends the template hash

   sha256 bank: extends a zero padded template hash

   Type 2: For a transition kernel that correctly extends SHA-256, etc, but does not have a hash
   agile IMA log.  The template hash is calcaulated as a hash of the template data.

   In the future, support for a hash agile IMA log is anticipated.
*/

/* Design:  The inner loop reads and parses each IMA event.  Then:

   addDigest() populates a PCR_Extend_In structure.

   then:

   If the TPM is being used, TSS_Execute() is called.

   For a simulation, extendDigest() is called.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TPM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef TPM_POSIX
#include <unistd.h>
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssutils.h>

#include "imalib.h"

/* local prototypes */

static TPM_RC addDigest(PCR_Extend_In 	*pcrExtendIn,
			int 		type,
			ImaEvent 	*imaEvent);
static TPM_RC checkTemplateHash(ImaEvent 	*imaEvent,
				int 		type,
				int 		eventNum);
static TPM_RC extendDigest(TPMT_HA 		simPcrs[][IMPLEMENTATION_PCR],
			   PCR_Extend_In	*pcrExtendIn);
static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      PCR_Read_In *pcrReadIn,
		      TPMI_DH_PCR pcrHandle);
static void printUsage(void);

extern int tssUtilsVerbose;
int vverbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 		rc = 0;
    int 		i = 0;
    TSS_CONTEXT		*tssContext = NULL;
    PCR_Extend_In 	pcrExtendIn;
    PCR_Read_In 	pcrReadIn;
    const char 		*infilename = NULL;
    const char 		*outfilename = NULL;
    FILE 		*infile = NULL;
    int 		littleEndian = FALSE;
    int			type = 1;			/* IMA log type, default 1 */
    int			sim = FALSE;			/* extend into simulated PCRs */
    int			checkHash = FALSE;		/* verify IMA log hashes */
    int			checkData = FALSE;		/* verify IMA log template data */
    uint32_t 		bankNum = 0;			/* PCR hash bank iterator */
    unsigned int 	pcrNum = 0;			/* PCR number iterator */
    TPMT_HA 		simPcrs[HASH_COUNT][IMPLEMENTATION_PCR];
    unsigned long	beginEvent = 0;			/* default beginning of log */
    unsigned long	endEvent = 0xffffffff;		/* default end of log */
    unsigned int	loopTime = 0;			/* default no loop */
    ImaEvent 		imaEvent;
    unsigned int 	lineNum;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    /* no hash algorithms specified yet */
    pcrExtendIn.digests.count = 0; 
    pcrReadIn.pcrSelectionIn.count = 0;

    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		infilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of")  == 0) {
	    i++;
	    if (i < argc) {
		outfilename = argv[i];
	    } else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    pcrExtendIn.digests.count++;	/* count number of algoriths specified */
	    pcrReadIn.pcrSelectionIn.count++;
	    if (pcrExtendIn.digests.count > HASH_COUNT) {
		printf("Too many -halg specifiers, %u permitted\n", HASH_COUNT);
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    pcrExtendIn.digests.digests[pcrExtendIn.digests.count-1].hashAlg =
			TPM_ALG_SHA1;
		    pcrReadIn.pcrSelectionIn.pcrSelections[pcrReadIn.pcrSelectionIn.count-1].hash =
			TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    pcrExtendIn.digests.digests[pcrExtendIn.digests.count-1].hashAlg =
			TPM_ALG_SHA256;
		    pcrReadIn.pcrSelectionIn.pcrSelections[pcrReadIn.pcrSelectionIn.count-1].hash =
			TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    pcrExtendIn.digests.digests[pcrExtendIn.digests.count-1].hashAlg =
			TPM_ALG_SHA384;
		    pcrReadIn.pcrSelectionIn.pcrSelections[pcrReadIn.pcrSelectionIn.count-1].hash =
			TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    pcrExtendIn.digests.digests[pcrExtendIn.digests.count-1].hashAlg =
			TPM_ALG_SHA512;
		    pcrReadIn.pcrSelectionIn.pcrSelections[pcrReadIn.pcrSelectionIn.count-1].hash =
			TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-tpm") == 0) {
	    sim = FALSE;
	}
	else if (strcmp(argv[i],"-sim") == 0) {
	    sim = TRUE;
	}
	else if (strcmp(argv[i],"-checkhash") == 0) {
	    checkHash = TRUE;
	}
	else if (strcmp(argv[i],"-checkdata") == 0) {
	    checkData = TRUE;
	}
	else if (strcmp(argv[i],"-ty") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &type);
		if ((type != 1) && (type != 2)) {
		    printf("Bad parameter %s for -ty\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-ty option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-le") == 0) {
	    littleEndian = TRUE; 
	}
	else if (strcmp(argv[i],"-b") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%lu", &beginEvent);
	    }
	    else {
		printf("Missing parameter for -b\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-e") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%lu", &endEvent);
	    }
	    else {
		printf("Missing parameter for -e\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-l") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &loopTime);
	    }
	    else {
		printf("Missing parameter for -e\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    tssUtilsVerbose = TRUE;
	    vverbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (infilename == NULL) {
	printf("Missing -if argument\n");
	printUsage();
    }
    /* if no -halg algorithms specified, default to sha1 and sha256 */
    if (pcrReadIn.pcrSelectionIn.count == 0) {
	pcrExtendIn.digests.count = 2;
	pcrReadIn.pcrSelectionIn.count = 2;
	pcrExtendIn.digests.digests[0].hashAlg = TPM_ALG_SHA1;
	pcrExtendIn.digests.digests[1].hashAlg = TPM_ALG_SHA256;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA1;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].hash = TPM_ALG_SHA256;
    }
    /* type 1 IMA logs zero extend into the SHA-256 bank */
    if ((rc == 0) && (type == 1)) {
	for (bankNum = 0 ; bankNum < pcrExtendIn.digests.count ; bankNum++) {
	    memset((uint8_t *)&pcrExtendIn.digests.digests[bankNum].digest, 0, sizeof(TPMU_HA));
	}
    }
    /* extending into TPM PCRs */
    if (!sim) {
	/* Start a TSS context */
	if (rc == 0) {
	    rc = TSS_Create(&tssContext);
	}
	if ((rc == 0) && tssUtilsVerbose) {	/* for debug */
	    printf("Initial PCR 10 value\n");
	    rc = pcrread(tssContext, &pcrReadIn, 10);
	}
    }
    else {	/* sim TRUE */
	/* simulated PCRs start at zero at boot */
	if (rc == 0) {
	    for (bankNum = 0 ; bankNum < pcrExtendIn.digests.count ; bankNum++) {
		for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		    /* initialize each algorithm ID */
		    simPcrs[bankNum][pcrNum].hashAlg = pcrExtendIn.digests.digests[bankNum].hashAlg;
		    memset(&simPcrs[bankNum][pcrNum].digest.tssmax, 0,
			   sizeof(simPcrs[bankNum][pcrNum].digest.tssmax));
		}
	    }
	}
    }
    /*
      scan each measurement 'line' in the binary
    */
    do {
	/* read the IMA event log file */
	int endOfFile = FALSE;
	if (rc == 0) {
	    /* ignore VS false positive, infilename checked for NULL above */
	    infile = fopen(infilename,"rb");
	    if (infile == NULL) {
		printf("Unable to open input file '%s'\n", infilename);
		rc = TSS_RC_FILE_OPEN;
	    }
	}
	for (lineNum = 0 ; (rc == 0) && !endOfFile ; lineNum++) {
	    /* read an IMA event line */
	    IMA_Event_Init(&imaEvent);
	    if (rc == 0) {
		rc = IMA_Event_ReadFile(&imaEvent, &endOfFile, infile,
					littleEndian);
	    }
	    /*
	      if the event line is in range
	    */
	    if ((rc == 0) && (lineNum >= beginEvent) && (lineNum <= endEvent) && !endOfFile) {
		/* debug tracing */
		if (rc == 0) {
		    ImaTemplateData imaTemplateData;
		    if (tssUtilsVerbose) printf("\n");
		    printf("imaextend: line %u\n", lineNum);
		    if (tssUtilsVerbose) {
			IMA_Event_Trace(&imaEvent, FALSE);
			/* unmarshal the template data */
			if (rc == 0) {
			    rc = IMA_TemplateData_ReadBuffer(&imaTemplateData,
							     &imaEvent,
							     littleEndian);
			}
			if (rc == 0) {
			    IMA_TemplateData_Trace(&imaTemplateData,
						   imaEvent.nameInt);
			}
			else {
			    printf("imaextend: Error parsing template data, event %u\n", lineNum);
			    if (!checkData) {
				rc = 0;		/* not a fatal error */
			    }
			}
		    }
		}
		/* add the digest to be extended into the PCR_Extend_In banks */
		if (rc == 0) {
		    rc = addDigest(&pcrExtendIn, type, &imaEvent);
		}
		if ((rc == 0) && checkHash) {
		    rc = checkTemplateHash(&imaEvent, type, lineNum);
		}
		if (rc == 0) {
		    pcrExtendIn.pcrHandle = imaEvent.pcrIndex;		/* normally PCR 10 */
		    /* even though IMA_Event_ReadFile() range checks the PCR index, range check it
		       again here to silence the static analysis tool */
		    if (imaEvent.pcrIndex >= IMPLEMENTATION_PCR) {
			printf("imaextend: PCR index %u %08x out of range\n",
			       imaEvent.pcrIndex, imaEvent.pcrIndex);
			rc = TSS_RC_BAD_PROPERTY_VALUE;
		    }
		}
		if (!sim) {	/* extend into TPM PCRs */
		    if (rc == 0) {
			rc = TSS_Execute(tssContext,
					 NULL, 
					 (COMMAND_PARAMETERS *)&pcrExtendIn,
					 NULL,
					 TPM_CC_PCR_Extend,
					 TPM_RS_PW, NULL, 0,
					 TPM_RH_NULL, NULL, 0);
		    }
		    if (rc == 0 && tssUtilsVerbose) {	/* debug reace PCR result */
			rc = pcrread(tssContext, &pcrReadIn, imaEvent.pcrIndex);
		    }
		}
		else {		/* sim */
		    if (rc == 0) {
			rc = extendDigest(simPcrs, &pcrExtendIn);
		    }
		}
	    }
	    IMA_Event_Free(&imaEvent);
	}	/* for each IMA event line */
	if (tssUtilsVerbose && (loopTime != 0)) printf("set beginEvent to %u\n", lineNum-1);
	beginEvent = lineNum-1;		/* remove the last increment at EOF */
	if (infile != NULL) {
	    fclose(infile);
	}
#ifdef TPM_POSIX
	sleep(loopTime);
#endif
#ifdef TPM_WINDOWS
	Sleep(loopTime * 1000);
#endif
    } while ((rc == 0) && (loopTime != 0)); 		/* sleep loop */
    if (!sim) {
	TPM_RC rc1 = TSS_Delete(tssContext);		/* close the TPM connection */
	if (rc == 0) {
	    rc = rc1;
	}
    }
    else {	/* sim, trace the simulated PCR result */
	uint16_t 	digestSize;
	for (bankNum = 0 ; (rc == 0) && (bankNum < pcrExtendIn.digests.count) ; bankNum++) {
	    TSS_TPM_ALG_ID_Print("algorithmId", simPcrs[bankNum][0].hashAlg, 0);
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	        char 		pcrString[9];	/* PCR number */
		sprintf(pcrString, "PCR %02u:", pcrNum);
		/* TSS_PrintAllLogLevel() with a log level of LOGLEVEL_INFO to print the byte
		   array on one line with no length */
		digestSize = TSS_GetDigestSize(simPcrs[bankNum][pcrNum].hashAlg);
		TSS_PrintAllLogLevel(LOGLEVEL_INFO, pcrString, 1,
				     simPcrs[bankNum][pcrNum].digest.tssmax,
				     digestSize);
	    }
	}
	/* write PCR 10 for the first hash algorithm, for the regression test */
	if ((rc == 0) && (outfilename != NULL)) {
	    digestSize = TSS_GetDigestSize(simPcrs[0][10].hashAlg);
	    rc = TSS_File_WriteBinaryFile(simPcrs[0][10].digest.tssmax,
					  digestSize,
					  outfilename);
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("imaextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("imaextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* checkTemplateHash() validates the IMA event SHA-1 template hash against the hash of the template
   data. */

static TPM_RC checkTemplateHash(ImaEvent 	*imaEvent,
				int 		type,
				int 		eventNum)
{
    TPM_RC 		rc = 0;
    int 		notAllZero;
    unsigned char 	zeroDigest[SHA1_DIGEST_SIZE];	/* compare to SHA-1 digest in event log */
    uint32_t 		badEvent;

    type = type;	/* unused until a hash agile log is supported */
    if (rc == 0) {
	memset(zeroDigest, 0, sizeof(zeroDigest));
	notAllZero = memcmp(imaEvent->digest, zeroDigest, sizeof(zeroDigest));
    }
    if ((rc == 0) && notAllZero) {
	rc = IMA_VerifyImaDigest(&badEvent, 	/* TRUE if hash does not match */
				 imaEvent, 	/* the current IMA event being processed */
				 eventNum);	/* the current IMA event number being processed */
	if ((rc == 0) && badEvent) {
	    printf("imaextend: Hash of template data does not match template hash\n");
	    rc = TSS_RC_HASH;
	}
    }
    return rc;
}

/* addDigest() adds the digests to the pcrExtendIn structure.  It is used before extending either
   the TPM PCRs of the simulated PCRs.

   The sha1 digest comes from the imaEvent->digest field.

   Type 1: The other digests are copied to the already 0 extended other banks
   Type 2: The other digests are a hash of the template data field.

   This function also handles the zeros to ones IMA quirk.
*/

static TPM_RC addDigest(PCR_Extend_In 	*pcrExtendIn,
			int 		type,
			ImaEvent 	*imaEvent)
{
    TPM_RC 		rc = 0;
    uint32_t 		bankNum = 0;				/* PCR hash bank interator */
    uint8_t 		zeroDigest[SHA1_DIGEST_SIZE];
    int 		notAllZero;
    uint16_t 		digestSize;

    /* determine if the template hash (always sha1) is all zeros */
    if (rc == 0) {
	memset(zeroDigest, 0, sizeof(zeroDigest));
	notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
    }
    for (bankNum = 0 ; bankNum < pcrExtendIn->digests.count ; bankNum++) {

	if (type == 1) {
	    if (notAllZero) {
		memcpy((uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest,
		       imaEvent->digest, SHA1_DIGEST_SIZE);
	    }
	    /* IMA has a quirk where some measurements store a zero digest in the event log, but
	       extend ones into PCR 10 */
	    else {
		memset((uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest,
		       0xff, SHA1_DIGEST_SIZE);
	    }
	}
	else if (type == 2) {
	    digestSize = TSS_GetDigestSize(pcrExtendIn->digests.digests[bankNum].hashAlg);

	    if (notAllZero) {
		/* sha1 gets the imaEvent->digest field directly */
		if (pcrExtendIn->digests.digests[bankNum].hashAlg == TPM_ALG_SHA1) {
		    memcpy((uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest,
			   imaEvent->digest, SHA1_DIGEST_SIZE);
		}
		/* other hash algorithms get the digest of template data */
		else {
		    TPMT_HA *tpmtHa = &pcrExtendIn->digests.digests[bankNum];
		    rc = TSS_Hash_Generate(tpmtHa,
					   (int)imaEvent->template_data_len, imaEvent->template_data,
					   0, NULL);
		}
	    }
	    /* if all zero */
	    else {
		/* IMA has a quirk where some measurements store a zero digest in the event log, but
		   extend ones into PCR 10 */
		memset((uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest, 0xff, digestSize);
	    }
	}
    }
    return rc;
}

static TPM_RC extendDigest(TPMT_HA 		simPcrs[][IMPLEMENTATION_PCR],
			   PCR_Extend_In	*pcrExtendIn)
{
    TPM_RC 		rc = 0;
    uint32_t 		bankNum = 0;
    /* PCR hash bank interator */
    TPMI_DH_PCR 	pcrHandle;
    uint16_t 		digestSize;

    /* index range check */
    if (rc == 0) {
	pcrHandle = pcrExtendIn->pcrHandle;
	if (pcrHandle >= IMPLEMENTATION_PCR) {
	    printf("extendDigest: PCR index %u %08x out of range\n", pcrHandle, pcrHandle);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    for (bankNum = 0 ; bankNum < pcrExtendIn->digests.count ; bankNum++) {
	digestSize = TSS_GetDigestSize(pcrExtendIn->digests.digests[bankNum].hashAlg);
#if 0
	TSS_PrintAll("extendDigest: extending",
		     (uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest,
		     digestSize);
#endif
	if (rc == 0) {
	    rc = TSS_Hash_Generate(&simPcrs[bankNum][pcrHandle],
				   digestSize,
				   (uint8_t *)&simPcrs[bankNum][pcrHandle].digest,
				   digestSize,
				   (uint8_t *)&pcrExtendIn->digests.digests[bankNum].digest,
				   0, NULL);
	}
	if (rc == 0 && tssUtilsVerbose) {
	    TSS_TPM_ALG_ID_Print("Simulated PCR bank",
				 pcrExtendIn->digests.digests[bankNum].hashAlg,
				 0);
	    TSS_PrintAll("PCR digest",
			 simPcrs[bankNum][pcrHandle].digest.tssmax,
			 digestSize);
	}
    }
    return rc;
}

/* for debug, read back and trace the PCR value before and after the extend */

static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      PCR_Read_In *pcrReadIn,
		      TPMI_DH_PCR pcrHandle)
{
    TPM_RC 		rc = 0;
    uint32_t 		count;
    PCR_Read_Out 	pcrReadOut;

    /* set the selection bitmap based on the pcrHandle */
    for (count = 0 ; (rc == 0) && (count < pcrReadIn->pcrSelectionIn.count) ; count++) {
	pcrReadIn->pcrSelectionIn.pcrSelections[count].sizeofSelect = 3;
	pcrReadIn->pcrSelectionIn.pcrSelections[count].pcrSelect[0] = 0;
	pcrReadIn->pcrSelectionIn.pcrSelections[count].pcrSelect[1] = 0;
	pcrReadIn->pcrSelectionIn.pcrSelections[count].pcrSelect[2] = 0;
	pcrReadIn->pcrSelectionIn.pcrSelections[count].pcrSelect[pcrHandle / 8] =
	    1 << (pcrHandle % 8);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&pcrReadOut,
			 (COMMAND_PARAMETERS *)pcrReadIn,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
    }
    /* the banks requested may not all be allocated.  Use pcrReadOut, not pcrReadIn */
    if (rc == 0) {
	if (pcrReadOut.pcrValues.count == 0) {
	    printf("No PCR banks\n");
	}
    }
    for (count = 0 ; (rc == 0) && (count < pcrReadOut.pcrValues.count) ; count++) {
	TSS_TPM_ALG_ID_Print("PCR bank",
			     pcrReadOut.pcrSelectionOut.pcrSelections[count].hash,
			     0);
	TSS_PrintAll("PCR digest",
		     pcrReadOut.pcrValues.digests[count].t.buffer,
		     pcrReadOut.pcrValues.digests[count].t.size);
    }
   return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("imaextend\n");
    printf("\n");
    printf("Replays the provided IMA event log.\n"
	   "\n"
	   "Without -sim, uses TPM2_PCR_Extend to extend the events into the TPM.\n"
	   "With    -sim, extends into simulated PCRs and traces the result.\n"
	   "\n"
	   "Without -sim, hash algorithms not allocated are ignored, the TPM behavior.\n"
	   "With    -sim, all specified hash algorithms are used.\n"
	   "If no hash algorithms are specified, defaults to sha1 and sha256.\n"
	   "\n"
	   "Two IMA log formats are currently supported:\n"
	   "\n"
	   "1: SHA1 - A zero padded measurement is extended into other PCR banks.\n"
	   "2: SHA1 - A digest of the template data is extended into other PCR banks.\n");
    printf("\n");
    printf("This handles the case where a zero measurement extends ones into the IMA PCR.\n");
    printf("\n");
    printf("\t-if\tIMA event log file name\n");
    printf("\t[-of\tWith -sim, PCR 10 of first algorithm specified]\n");
    printf("\t[-le\tinput file is little endian (default big endian)]\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512)]\n"
	   "\t\t-halg may be specified more than once\n");
    printf("\t[-ty\tIMA log format (default type 1)]\n");
    printf("\t[-tpm\textend TPM PCRs (default)]\n");
    printf("\t[-sim\tcalculate simulated PCRs]\n");
    printf("\t[-checkhash\tverify IMA event log hashes]\n");
    printf("\t[-checkdata\tverify IMA event log template data, stop on error]\n");
    printf("\t[-b\tbeginning entry (default 0, beginning of log)]\n");
    printf("\t\tA beginning entry after the end of the log becomes a noop\n");
    printf("\t[-e\tending entry (default end of log)]\n");
    printf("\t\tE.g., -b 0 -e 0 sends one entry\n");
    printf("\t[-l\ttime - run in a continuous loop, sleep 'time' seconds betwteen loops]\n");
    printf("\t\tThe intent is that this be run without specifying -b and -e\n");
    printf("\t\tAfer each pass, the next beginning entry is set to the last entry +1\n");
    printf("\n");
    exit(1);
}

