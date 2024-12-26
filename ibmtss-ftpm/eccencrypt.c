/********************************************************************************/
/*										*/
/*			   ECC_Encrypt						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2022						*/
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

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    ECC_Encrypt_In 		in;
    ECC_Encrypt_Out 		out;
    TPMI_DH_OBJECT		keyHandle = 0;
    const char			*decryptFilename = NULL;
    const char			*c1Filename = NULL;
    const char			*c2Filename = NULL;
    const char			*c3Filename = NULL;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    /* command line argument defaults */
    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA256;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-id") == 0) {
	    i++;
	    if (i < argc) {
		decryptFilename = argv[i];
	    }
	    else {
		printf("-id option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    in.inScheme.details.mgf1.hashAlg = TPM_ALG_SHA512;
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
	else if (strcmp(argv[i],"-oc1") == 0) {
	    i++;
	    if (i < argc) {
		c1Filename = argv[i];
	    }
	    else {
		printf("-oc1 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oc2") == 0) {
	    i++;
	    if (i < argc) {
		c2Filename = argv[i];
	    }
	    else {
		printf("-oc2 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oc3") == 0) {
	    i++;
	    if (i < argc) {
		c3Filename = argv[i];
	    }
	    else {
		printf("-oc3 option needs a value\n");
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
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (decryptFilename == NULL) {
	printf("Missing decrypted file -id\n");
	printUsage();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	rc = TSS_File_Read2B(&in.plainText.b,
			     sizeof(in.plainText.t.buffer),
			     decryptFilename);
    }
    if (rc == 0) {
	/* Handle of key that will perform ecc encrypting */
	in.keyHandle = keyHandle;
	/* the only scheme that the TPM supports */
	in.inScheme.scheme = TPM_ALG_KDF2;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ECC_Encrypt,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (c1Filename != NULL)) {
	rc = TSS_File_WriteStructure(&out.C1,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     c1Filename);
    }
    if ((rc == 0) && (c2Filename != NULL)) {
	rc = TSS_File_WriteStructure(&out.C2,
				     (MarshalFunction_t)TSS_TPM2B_MAX_BUFFER_Marshalu,
				     c2Filename);
    }
    if ((rc == 0) && (c3Filename != NULL)) {
 	rc = TSS_File_WriteStructure(&out.C3,
				     (MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu,
				     c3Filename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("eccencrypt: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eccencrypt: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("eccencrypt\n");
    printf("\n");
    printf("Runs TPM2_ECC_Encrypt\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t-id\tdecrypt file name\n");
    printf("\t[-oc1\tC1 ECC point file name (default do not save)]\n");
    printf("\t[-oc2\tC2 data buffer file name (default do not save)]\n");
    printf("\t[-oc3\tc3 integrity digest file name (default do not save)]\n");
    exit(1);
}
