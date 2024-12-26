/********************************************************************************/
/*										*/
/*			    NV SetBits		 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2024.					*/
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

/*

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>

static TPM_RC calculateParameterHash(const NV_SetBits_In *in,
				     const TPMI_ALG_HASH halg,
				     const char *pHashFilename);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_SetBits_In 		in;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    TPMI_ALG_HASH 		halg = TPM_ALG_NULL;		/* no default */
    int				pHash = FALSE;			/* default run command */
    const char 			*pHashFilename;			/* binary output */
    const char			*nvPassword = NULL; 		/* default no password */
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    in.bits = 0;	/* default no bits */

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-bit") == 0) {
	    unsigned int bit;
	    i++;
	    if (i < argc) {
		bit = atoi(argv[i]);
		if (bit < 64) {
		    in.bits |= (uint64_t)1 << bit;
		}
		else {
		    printf("-bit out of range\n");
		    printUsage();
		}
	    }
	    else {
		printf("-bit option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-phash") == 0) {
	    pHash = TRUE;
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    halg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -phash algorithm\n", argv[i]);
		    printUsage();
		}
	    }
	    i++;
	    if (i < argc) {
		pHashFilename = argv[i];
	    }
	    else {
		printf("-phash option needs two values\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if ((nvIndex >> 24) != TPM_HT_NV_INDEX) {
	printf("NV index handle not specified or out of range, MSB not 01\n");
	printUsage();
    }
    if (rc == 0) {
	in.authHandle = nvIndex;
	in.nvIndex = nvIndex;
    }
    /* run the command */
    if (!pHash) {
	/* Start a TSS context */
	if (rc == 0) {
	    rc = TSS_Create(&tssContext);
	}
	/* call TSS to execute the command */
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_SetBits,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	{
	    TPM_RC rc1 = TSS_Delete(tssContext);
	    if (rc == 0) {
		rc = rc1;
	    }
	}
	if (rc == 0) {
	    if (tssUtilsVerbose) printf("nvsetbits: success\n");
	}
    }
    /* calculate pHash */
    else {
	if (rc == 0) {
	    rc = calculateParameterHash(&in, halg, pHashFilename);
	}
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvsetbits: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* calculateParameterHash() calculates the parameter hash, suitable for input to a policyparameters
   calculation */

static TPM_RC calculateParameterHash(const NV_SetBits_In *in,
				     const TPMI_ALG_HASH halg,
				     const char *pHashFilename)
{
    TPM_RC 	rc = 0;
    uint8_t 	pBuffer[MAX_COMMAND_SIZE];	/* the marshalled parameters */
    TPM_CC 	commandCode = TPM_CC_NV_SetBits;
    TPM_CC	commandCodeNbo = htonl(commandCode);
    uint16_t 	parameterSize = 0;		/* the marshalled parameter size */
    uint32_t 	sizeInBytes;
    TPMT_HA	digest;
    uint8_t 	*paramPtr = pBuffer;	/* because the marshal function moves the pointer */
    uint32_t 	sizeLeft = sizeof(pBuffer);

    /* marshal the input parameters */
    if (rc == 0) {
	rc = TSS_NV_SetBits_In_Marshalu(in, &parameterSize, &paramPtr, &sizeLeft);
    }
    /* calculate the parameter hash */
    if (rc == 0) {
	/* move the pointer and size past the handle area, this command has two handles */
	paramPtr = pBuffer + (2 * (sizeof(TPM_HANDLE)));
	parameterSize -= (2 * (sizeof(TPM_HANDLE)));
	if (tssUtilsVerbose) TSS_PrintAll("pBuffer", pBuffer, parameterSize);
	sizeInBytes = TSS_GetDigestSize(halg);
	digest.hashAlg = halg;			/* session digest algorithm */
	rc = TSS_Hash_Generate(&digest,		/* largest size of a digest */
			       sizeof(TPM_CC), &commandCodeNbo,
			       parameterSize, paramPtr,
			       0, NULL);
    }
    /* putput as hexascii for policymaker input */
    if (rc == 0) {
	uint32_t i;
	for (i = 0 ; i < sizeInBytes ; i++) {
	    printf("%02x", digest.digest.tssmax[i]);
	}
	printf("\n");
    }
    /* output as binary for policyparameters input */
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(digest.digest.tssmax,
				      sizeInBytes,
				      pHashFilename);
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvsetbits\n");
    printf("\n");
    printf("Runs TPM2_NV_SetBits\n");
    printf("\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t[-pwdn\tpassword for NV index (default empty)]\n");
    printf("\t[-bit\tbit to set, can be specified multiple times]\n");
    printf("\t[-phash\tpolicy hash algorithm (sha1, sha256, sha384, sha512)]\n"
	   "\t\tand binary output file name\n");
    printf("\t\tOutputs the parameter hash, does not run the command\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    exit(1);
}
