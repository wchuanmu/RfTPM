/********************************************************************************/
/*										*/
/*			     IMA Routines					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2023.					*/
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

/* imalib is a set of utility functions to handle IMA (Integrity Measurement Architecture) event
   logs.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef TPM_POSIX
#include <arpa/inet.h>
#endif

#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#ifndef TPM_TSS_NO_OPENSSL
#include <openssl/x509.h>
#include <openssl/bio.h>
#endif	/* TPM_TSS_NO_OPENSSL */

#include <ibmtss/TPM_Types.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>

#include "imalib.h"

/* IMA template names */

#define IMA_UNSUPPORTED		0
#define IMA_FORMAT_IMA_NG	1
#define IMA_FORMAT_IMA_SIG	2
#define IMA_FORMAT_IMA		3
#define IMA_FORMAT_IMA_MODSIG	4
#define IMA_FORMAT_IMA_BUF	5
#define IMA_FORMAT_IMA_NGV2	6
#define IMA_FORMAT_IMA_SIGV2	7
#define IMA_FORMAT_EVM_SIG	8

static uint32_t IMA_Uint16_Unmarshal(uint16_t 	*out,
				     uint8_t 	**buffer,
				     size_t 	*length,
				     int 	littleEndian);
static uint32_t IMA_Uint32_Unmarshal(uint32_t 	*out,
				     uint8_t 	**buffer,
				     size_t 	*length,
				     int 	littleEndian);
static uint32_t IMA_Uint32_Convert(const uint8_t *stream,
				   int littleEndian);
static uint32_t IMA_Strn2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength);
static uint32_t IMA_Strc2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength);
static void IMA_Event_ParseName(ImaEvent *imaEvent);

static uint32_t IMA_TemplateData_ReadFile(ImaEvent *imaEvent,
					  int *endOfFile,
					  FILE *inFile,
					  int littleEndian);
static uint32_t IMA_TemplateDataIma_ReadFile(ImaEvent *imaEvent,
					     int *endOfFile,
					     FILE *inFile,
					     int littleEndian);

/* callback to parse a template data field */

typedef uint32_t (*TemplateDataParseFunction_t)(ImaTemplateData	*imaTemplateData,
						uint8_t 	**buffer,
						size_t 		*length,
						int 		littleEndian);
static uint32_t IMA_TemplateName_Parse(TemplateDataParseFunction_t templateDataParseFunctions[],
				       TemplateDataTraceFunction_t templateDataTraceFunctions[],
				       size_t templateDataParseFunctionsSize,
				       ImaEvent *imaEvent);
static uint32_t
IMA_TemplateName_ParseCustom(TemplateDataParseFunction_t templateDataParseFunctions[],
			     TemplateDataTraceFunction_t templateDataTraceFunctions[],
			     size_t templateDataParseFunctionsSize,
			     ImaEvent *imaEvent);
static uint32_t IMA_ParseD(ImaTemplateData	*imaTemplateData,
			   uint8_t 		**buffer,
			   size_t 		*length,
			   int 			littleEndian);
static uint32_t IMA_ParseDNG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian);
static uint32_t IMA_ParseDNGV2(ImaTemplateData	*imaTemplateData,
			       uint8_t 		**buffer,
			       size_t 		*length,
			       int 		littleEndian);
static uint32_t IMA_ParseNNG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian);
static uint32_t IMA_ParseSIG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian);
static uint32_t IMA_ParseDMODSIG(ImaTemplateData	*imaTemplateData,
				 uint8_t 		**buffer,
				 size_t 		*length,
				 int 			littleEndian);
static uint32_t IMA_ParseMODSIG(ImaTemplateData	*imaTemplateData,
				uint8_t 	**buffer,
				size_t 		*length,
				int 		littleEndian);
static uint32_t IMA_ParseBUF(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian);
static uint32_t IMA_ParseXATTRNAMES(ImaTemplateData	*imaTemplateData,
				    uint8_t 		**buffer,
				    size_t 		*length,
				    int 		littleEndian);
static uint32_t IMA_ParseXATTRLENGTHS(ImaTemplateData	*imaTemplateData,
				      uint8_t 		**buffer,
				      size_t 		*length,
				      int 		littleEndian);
static uint32_t IMA_ParseXATTRVALUES(ImaTemplateData	*imaTemplateData,
				     uint8_t 		**buffer,
				     size_t 		*length,
				     int 		littleEndian);
static uint32_t IMA_ParseIUID(ImaTemplateData	*imaTemplateData,
			      uint8_t 		**buffer,
			      size_t 		*length,
			      int 		littleEndian);
static uint32_t IMA_ParseIGID(ImaTemplateData	*imaTemplateData,
			      uint8_t 		**buffer,
			      size_t 		*length,
			      int 		littleEndian);
static uint32_t IMA_ParseIMODE(ImaTemplateData	*imaTemplateData,
			       uint8_t 		**buffer,
			       size_t 		*length,
			       int 		littleEndian);

extern int tssUtilsVerbose;

/* IMA_Event_Init() initializes the ImaEvent structure so that IMA_Event_Free() is safe.

 */

void IMA_Event_Init(ImaEvent *imaEvent)
{
    if (imaEvent != NULL) {
	imaEvent->nameInt = IMA_UNSUPPORTED;
	imaEvent->template_data = NULL;
    }
    return;
}

/* IMA_Event_Free() frees any memory allocated for the ImaEvent structure.

 */

void IMA_Event_Free(ImaEvent *imaEvent)
{
    if (imaEvent != NULL) {
	free(imaEvent->template_data);
	imaEvent->template_data = NULL;
    }
    return;
}

/* IMA_Event_Trace() traces the ImaEvent structure.

   If traceTemplate is FALSE, template data is not traced.  This handles the case where template
   data is not unmarshaled.

*/

void IMA_Event_Trace(ImaEvent *imaEvent, int traceTemplate)
{
    printf("IMA_Event_Trace: PCR index %u\n", imaEvent->pcrIndex);
    TSS_PrintAll("IMA_Event_Trace: hash",
		 imaEvent->digest, sizeof(((ImaEvent *)NULL)->digest));

    printf("IMA_Event_Trace: name length %u\n", imaEvent->name_len);
    printf("IMA_Event_Trace: name text %s\n", imaEvent->name);
#if 1
    printf("IMA_Event_Trace: name integer %u\n", imaEvent->nameInt);
    TSS_PrintAll("IMA_Event_Trace: template data",
		 imaEvent->template_data, imaEvent->template_data_len);
#endif
    printf("IMA_Event_Trace: template data length %u\n", imaEvent->template_data_len);
    /* in some use cases, the template_data field is not populated.  In those cases, do not trace
       it. */
    if (traceTemplate) {
	TSS_PrintAll("IMA_Event_Trace: template data",
		     imaEvent->template_data, imaEvent->template_data_len);
    }
    return;
}

/* IMA_Event_ParseName() parses the Template Name and sets the nameInt field */

static void IMA_Event_ParseName(ImaEvent *imaEvent)
{
    if (strcmp(imaEvent->name, "ima-ng") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_NG;
    }
    else if (strcmp(imaEvent->name, "ima-sig") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_SIG;
    }
    else if (strcmp(imaEvent->name, "ima") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA;
    }
    else if (strcmp(imaEvent->name, "ima-modsig") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_MODSIG;
    }
    else if (strcmp(imaEvent->name, "ima-buf") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_BUF;
    }
    else if (strcmp(imaEvent->name, "ima-ngv2") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_NGV2;
    }
    else if (strcmp(imaEvent->name, "ima-sigv2") == 0) {
	imaEvent->nameInt = IMA_FORMAT_IMA_SIGV2;
    }
    else if (strcmp(imaEvent->name, "evm-sig") == 0) {
	imaEvent->nameInt = IMA_FORMAT_EVM_SIG;
    }
    /* the template data parser currently supports only these formats. */
    else {
	imaEvent->nameInt = IMA_UNSUPPORTED;
    }
    return;
}

void IMA_TemplateData_Init(ImaTemplateData *imaTemplateData)
{
    size_t i;
    imaTemplateData->imaTemplateDNG.hashLength = 0;
    imaTemplateData->imaTemplateDNG.hashAlgId = TPM_ALG_NULL;
    imaTemplateData->imaTemplateDNG.fileDataHashLength = 0;
    imaTemplateData->imaTemplateNNG.fileNameLength = 0;
    imaTemplateData->imaTemplateNNG.fileName[0] = '\0';
    imaTemplateData->imaTemplateSIG.sigLength = 0;
    imaTemplateData->imaTemplateSIG.sigHeaderLength = 0;
    imaTemplateData->imaTemplateSIG.signatureSize = 0;
    imaTemplateData->imaTemplateDMODSIG.dModSigHashLength = 0;
    imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength = 0;
    imaTemplateData->imaTemplateMODSIG.modSigLength = 0;
    imaTemplateData->imaTemplateBUF.bufLength = 0;
    imaTemplateData->imaTemplateXattrs.xattrNamesLength = 0;
    imaTemplateData->imaTemplateXattrs.xattrNames[0] = '\0';
    imaTemplateData->imaTemplateXattrs.xattrNamesLength = 0;
    for (i = 0 ;
	 i < ((sizeof(((ImaTemplateXattrs *)NULL)->xattrNamesPtr)) / (sizeof(char *))) ;
	 i++) {
	imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i] = NULL;
    }
    imaTemplateData->imaTemplateXattrs.xattrNamesCount = 0;
    imaTemplateData->imaTemplateXattrs.xattrLengthsSum = 0;
    imaTemplateData->imaTemplateXattrs.xattrValuesLength = 0;
    imaTemplateData->imaTemplateIUID.iuidLength = 0;
    imaTemplateData->imaTemplateIGID.igidLength = 0;
    imaTemplateData->imaTemplateIMODE.imodeLength = 0;
    return;
}

/* IMA_TemplateData_Trace() traces the ImaTemplateData  structure.

   nameInt maps to the template name.

*/

void IMA_TemplateData_Trace(ImaTemplateData *imaTemplateData,
			    unsigned int nameInt)
{
    size_t	i;

    nameInt = nameInt;	/* obsolete now that custom templates are supported */
    for (i = 0 ; imaTemplateData->templateDataTraceFunctions[i] != NULL ; i++) {
	imaTemplateData->templateDataTraceFunctions[i](imaTemplateData);
    }
    return;
}

/* Below are the callbacks to trace fields in ImaTemplateData */

static void IMA_TraceD(ImaTemplateData	*imaTemplateData)
{
    TSS_PrintAll("IMA_Template_Trace: D file data hash",
		 imaTemplateData->imaTemplateDNG.fileDataHash,
		 imaTemplateData->imaTemplateDNG.fileDataHashLength);
    return;
}
static void IMA_TraceDNG(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: DNG hashLength %u\n",
	   imaTemplateData->imaTemplateDNG.hashLength); 
    printf("IMA_TemplateData_Trace: DNG hashAlg %s\n", imaTemplateData->imaTemplateDNG.hashAlg);
    TSS_PrintAll("IMA_Template_Trace: DNG file data hash",
		 imaTemplateData->imaTemplateDNG.fileDataHash,
		 imaTemplateData->imaTemplateDNG.fileDataHashLength);
    return;
}
static void IMA_TraceDNGV2(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: DNGV2 hashLength %u\n",
	   imaTemplateData->imaTemplateDNGV2.hashLength); 
    printf("IMA_TemplateData_Trace: DNGV2 prefix %s\n", imaTemplateData->imaTemplateDNGV2.prefix);
    printf("IMA_TemplateData_Trace: DNGV2 hashAlg %s\n", imaTemplateData->imaTemplateDNGV2.hashAlg);
    TSS_PrintAll("IMA_Template_Trace: DNGV2 file data hash",
		 imaTemplateData->imaTemplateDNGV2.fileDataHash,
		 imaTemplateData->imaTemplateDNGV2.fileDataHashLength);
    return;
}
static void IMA_TraceNNG(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: NNG fileNameLength %u\n",
	   imaTemplateData->imaTemplateNNG.fileNameLength);
    if (imaTemplateData->imaTemplateNNG.fileNameLength > 0) {
	printf("IMA_TemplateData_Trace: NNG fileName %s\n",
	       imaTemplateData->imaTemplateNNG.fileName);
    }
    return;
}
static void IMA_TraceSIG(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: SIG sigLength %u\n", imaTemplateData->imaTemplateSIG.sigLength);
    if (imaTemplateData->imaTemplateSIG.sigLength != 0) {
	TSS_PrintAll("IMA_TemplateData_Trace: sigHeader",
		     imaTemplateData->imaTemplateSIG.sigHeader,
		     imaTemplateData->imaTemplateSIG.sigHeaderLength);
	printf("IMA_TemplateData_Trace: SIG signatureSize %u\n",
	       imaTemplateData->imaTemplateSIG.signatureSize);
	TSS_PrintAll("IMA_TemplateData_Trace: SIG signature",
		     imaTemplateData->imaTemplateSIG.signature,
		     imaTemplateData->imaTemplateSIG.signatureSize);
    }
    return;
}
static void IMA_TraceDMODSIG(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: DMODSIG dModSigHashLength %u\n",
	   imaTemplateData->imaTemplateDMODSIG.dModSigHashLength);
    if (imaTemplateData->imaTemplateDMODSIG.dModSigHashLength != 0) {
	printf("IMA_TemplateData_Trace: DMODSIG dModSigHashAlg %s\n",
	       imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg);
	TSS_PrintAll("IMA_Template_Trace: DMODSIG file data hash",
		     imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHash,
		     imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength);
    }
    return;
}
static void IMA_TraceMODSIG(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: MODSIG modSigLength %u\n",
	   imaTemplateData->imaTemplateMODSIG.modSigLength);
    if (imaTemplateData->imaTemplateMODSIG.modSigLength != 0) {
	TSS_PrintAll("IMA_TemplateData_Trace: MODSIG modSigData",
		     imaTemplateData->imaTemplateMODSIG.modSigData,
		     imaTemplateData->imaTemplateMODSIG.modSigLength);
#ifndef TPM_TSS_MBEDTLS
	{
	    PKCS7 		*pkcs7 = NULL;
	    unsigned char 	*tmpData = NULL; 
	    /* tmp pointer because d2i moves the pointer */
	    tmpData = imaTemplateData->imaTemplateMODSIG.modSigData;
	    pkcs7 = d2i_PKCS7(NULL,				/* freed @1 */
			      (const unsigned char **)&tmpData,
			      imaTemplateData->imaTemplateMODSIG.modSigLength);
	    if (pkcs7 != NULL) {
		BIO *bio = NULL;
#ifdef TPM_POSIX
		bio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);	/* freed @2 */
#endif
#ifdef TPM_WINDOWS
		bio = BIO_new_fd(_fileno(stdout), BIO_NOCLOSE);	/* freed @2 */
#endif
		if (bio != NULL) {
		    PKCS7_print_ctx(bio, pkcs7, 4, NULL);
		    BIO_free(bio);	/* @2 */
		}
		else {
		    printf("IMA_TemplateData_Trace: MODSIG Could not create BIO for PKCS7\n");
		}
		PKCS7_free(pkcs7);	/* @1 */
	    }
	    else {
		printf("IMA_TemplateData_Trace: MODSIG Could not trace modSigData as PKCS7\n");
	    }
	}
#endif /* TPM_TSS_MBEDTLS */
    }
    return;
}
static void IMA_TraceBUF(ImaTemplateData	*imaTemplateData)
{
    printf("IMA_TemplateData_Trace: BUF bufLength %u\n", imaTemplateData->imaTemplateBUF.bufLength);
    if (imaTemplateData->imaTemplateBUF.bufLength != 0) {
	TSS_PrintAll("IMA_TemplateData_Trace: BUF bufData",
		     imaTemplateData->imaTemplateBUF.bufData,
		     imaTemplateData->imaTemplateBUF.bufLength);
#ifndef TPM_TSS_MBEDTLS
	/* keys are X.509 certificates */
	if ((strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
		    ".builtin_trusted_keys") == 0) ||
	    (strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
		    ".platform") == 0) ||
	    (strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
		    ".machine") == 0) ||
	    (strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
		    ".evm") == 0) ||
	    (strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
		    ".ima") == 0)) {
	    {
		X509 		*x509 = NULL;
		unsigned char 	*tmpData = NULL;
		/* tmp pointer because d2i moves the pointer */
		tmpData = imaTemplateData->imaTemplateBUF.bufData;
		x509 = d2i_X509(NULL,				/* freed @1 */
				(const unsigned char **)&tmpData,
				imaTemplateData->imaTemplateBUF.bufLength);
		if (x509 != NULL) {
		    if (x509 != NULL) {
			X509_print_fp(stdout, x509);
			X509_free(x509);	/* @1 */
		    }
		    else {
			printf("IMA_TemplateData_Trace: BUF Could not trace bufData as X509\n");
		    }
		}
	    }
	}
	/* selinux state and kernel command line are printable, not nul terminated */
	else if ((strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
			 "selinux-state") == 0) ||
		 (strcmp((const char *)imaTemplateData->imaTemplateNNG.fileName,
			 "kexec-cmdline") == 0)) {
	    printf("    %.*s\n",
		   imaTemplateData->imaTemplateBUF.bufLength,
		   imaTemplateData->imaTemplateBUF.bufData);
	}
#endif /* TPM_TSS_MBEDTLS */
    }
    return;
}

static void IMA_TraceXATTRNAMES(ImaTemplateData	*imaTemplateData)
{
    size_t i;
    for (i = 0 ; i < imaTemplateData->imaTemplateXattrs.xattrNamesCount ; i++) {
	printf("IMA_TemplateData_Trace: xattrnames %s\n",
	       imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i]);
    }
    return;
}

static void IMA_TraceXATTRLENGTHS(ImaTemplateData	*imaTemplateData)
{
    size_t	i;

    for (i = 0 ; i < imaTemplateData->imaTemplateXattrs.xattrLengthsLength / 4 ; i++) {
	printf("IMA_TemplateData_Trace: xattrlengths index %u length %08x %u\n",
	       (unsigned int)i,
	       imaTemplateData->imaTemplateXattrs.xattrLengths[i],
	       imaTemplateData->imaTemplateXattrs.xattrLengths[i]);
    }
    return;
}

static void IMA_TraceXATTRVALUES(ImaTemplateData	*imaTemplateData)
{
    size_t i;
    size_t index = 0;	/* index into xattrValues buffer */

#if 0
    TSS_PrintAll("IMA_TemplateData_Trace: xattrvalues",
		 imaTemplateData->imaTemplateXattrs.xattrValues,
		 imaTemplateData->imaTemplateXattrs.xattrValuesLength);
#endif
    for (i = 0 ; i < imaTemplateData->imaTemplateXattrs.xattrNamesCount ; i++) {

	if (strcmp(imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i], "security.selinux") == 0) {
	    /* ensure that the selinux string is nul terminated */
	    if (imaTemplateData->imaTemplateXattrs.xattrValues
		[index + imaTemplateData->imaTemplateXattrs.xattrLengths[i] -1] == '\0') {
		printf("IMA_TemplateData_Trace: xattrvalue %lu %s\n",
		       (unsigned long)i,
		       (char *)&imaTemplateData->imaTemplateXattrs.xattrValues[index]);
	    }
	    else {
		printf("IMA_TemplateData_Trace: "
		       "security.selinux value not nul terminated at index %lu\n",
		       (unsigned long)
		       (index + imaTemplateData->imaTemplateXattrs.xattrLengths[i] -1));
	    }
	}
	else if (strcmp(imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i], "security.ima") == 0) {
	    if (imaTemplateData->imaTemplateXattrs.xattrLengths[i] < 2) {
		printf("IMA_TemplateData_Trace: xattrvalue security.ima length insufficient\n");
	    }
	    else {
		printf("IMA_TemplateData_Trace: xattrvalue security.ima %02x %02x\n",
		       imaTemplateData->imaTemplateXattrs.xattrValues[index],
		       imaTemplateData->imaTemplateXattrs.xattrValues[index+1]);
		TSS_PrintAll("IMA_TemplateData_Trace: xattrvalue security.ima digest",
			     &imaTemplateData->imaTemplateXattrs.xattrValues[index+2],
			     imaTemplateData->imaTemplateXattrs.xattrLengths[i] -2);
	    }
	}
	else {
	    printf("IMA_TemplateData_Trace: Trace of xattrname %s not supported\n",
		   imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i]);
	}

	/* move the index past the length for the next pass */
	index += imaTemplateData->imaTemplateXattrs.xattrLengths[i];
    }
    return;
}

static void IMA_TraceIUID(ImaTemplateData	*imaTemplateData)
{
    if (imaTemplateData->imaTemplateIUID.iuidLength == 2) {
	printf("IMA_TemplateData_Trace: iuid %u\n", imaTemplateData->imaTemplateIUID.iuid16);
    }
    else if (imaTemplateData->imaTemplateIUID.iuidLength == 4) {
	printf("IMA_TemplateData_Trace: iuid %u\n", imaTemplateData->imaTemplateIUID.iuid32);
    }
    else {
	printf("IMA_TemplateData_Trace: iuid length 0\n");
    }
    return;
}

static void IMA_TraceIGID(ImaTemplateData	*imaTemplateData)
{
    if (imaTemplateData->imaTemplateIGID.igidLength == 2) {
	printf("IMA_TemplateData_Trace: igid %u\n", imaTemplateData->imaTemplateIGID.igid16);
    }
    else if (imaTemplateData->imaTemplateIGID.igidLength == 4) {
	printf("IMA_TemplateData_Trace: igid %u\n", imaTemplateData->imaTemplateIGID.igid32);
    }
    else {
	printf("IMA_TemplateData_Trace: igid length 0\n");
    }
    return;
}

static void IMA_TraceIMODE(ImaTemplateData	*imaTemplateData)
{
    if (imaTemplateData->imaTemplateIMODE.imodeLength != 0) {
	printf("IMA_TemplateData_Trace: imode %04o\n", imaTemplateData->imaTemplateIMODE.imode);
    }
    else {
	printf("IMA_TemplateData_Trace: igid length 0\n");
    }
    return;
}

/* IMA_Event_ReadFile() reads one IMA event from a file.

   It currently supports these template formats:  ima, ima-ng, ima-sig.

   This is typically used at the client, reading from the pseudofile.
*/

uint32_t IMA_Event_ReadFile(ImaEvent *imaEvent,	/* freed by caller */
			    int *endOfFile,
			    FILE *inFile,
			    int littleEndian)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;
    
    imaEvent->template_data = NULL;		/* for free */

    /* read the IMA PCR index */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&(imaEvent->pcrIndex),
			 sizeof(((ImaEvent *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* PCR index endian convert */
    if ((rc == 0) && !(*endOfFile)) {
	imaEvent->pcrIndex = IMA_Uint32_Convert((uint8_t *)&imaEvent->pcrIndex, littleEndian);
	/* range check the PCR index */
	if (imaEvent->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: IMA_Event_ReadFile: PCR index %u %08x out of range\n",
		   imaEvent->pcrIndex, imaEvent->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }	
    /* read the IMA digest, this is hard coded to SHA-1 */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&(imaEvent->digest),
			 sizeof(((ImaEvent *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read digest, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the IMA name length */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&(imaEvent->name_len),
			 sizeof(((ImaEvent *)NULL)->name_len), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read name_len, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	imaEvent->name_len = IMA_Uint32_Convert((uint8_t *)&imaEvent->name_len, littleEndian);
    }
    /* bounds check the name length, leave a byte for the nul terminator */
    if ((rc == 0) && !(*endOfFile)) {
	if (imaEvent->name_len > (sizeof(((ImaEvent *)NULL)->name)) -1) {
	    printf("ERROR: IMA_Event_ReadFile: template name length too big: %u\n",
		   imaEvent->name_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the template name */
    if ((rc == 0) && !(*endOfFile)) {
	/* nul terminate first */
	memset(imaEvent->name, 0, sizeof(((ImaEvent *)NULL)->name));
	/* ignore VS warning, name_len is range checked above, no buffer overrun */
	readSize = fread(&(imaEvent->name),
			 imaEvent->name_len, 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read template name, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* record the template name as an int */
    if ((rc == 0) && !(*endOfFile)) {
	IMA_Event_ParseName(imaEvent);
    }
    if ((rc == 0) && !(*endOfFile)) {
	if (imaEvent->nameInt != IMA_FORMAT_IMA) {	/* standard format */
	    rc = IMA_TemplateData_ReadFile(imaEvent, endOfFile, inFile, littleEndian);
	}
	else {						/* unique 'ima' format */
	    rc = IMA_TemplateDataIma_ReadFile(imaEvent, endOfFile, inFile, littleEndian);
	}
    }
    return rc;
}

/* IMA_TemplateData_ReadFile() reads the template data as a pure array.  It handles the normal case
   of template data length plus template data.
*/

static uint32_t IMA_TemplateData_ReadFile(ImaEvent *imaEvent,	/* freed by caller */
					  int *endOfFile,
					  FILE *inFile,
					  int littleEndian)
{
    int rc = 0;
    size_t readSize;

    /* read template data length */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&(imaEvent->template_data_len),
			 sizeof(((ImaEvent *)NULL)->template_data_len ), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_TemplateData_ReadFile: could not read template_data_len, "
		       " returned %lu\n", (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	imaEvent->template_data_len =
	    IMA_Uint32_Convert((uint8_t *)&imaEvent->template_data_len,
			       littleEndian);
    }
    /* bounds check the template data length */
    if ((rc == 0) && !(*endOfFile)) {
	if (imaEvent->template_data_len > TCG_TEMPLATE_DATA_LEN_MAX) {
	    printf("ERROR: IMA_TemplateData_ReadFile: template data length too big: %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	imaEvent->template_data = malloc(imaEvent->template_data_len);
	if (imaEvent->template_data == NULL) {
	    printf("ERROR: IMA_TemplateData_ReadFile: "
		   "could not allocate template data, size %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	/* ignore VS warning, template_data_len is used for the malloc, no buffer overrun */
	readSize = fread(imaEvent->template_data,
			 imaEvent->template_data_len, 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_Event_ReadFile: could not read template_data, "
		       "returned %lu\n", (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    return rc;
}

/* IMA_TemplateDataIma_ReadFile() reads the template data.  It handles the special case of the
   template name 'ima', which does not have a template data length.  'ima' has a 20 byte file data
   hash, a 4 byte file name length, and a file name.
*/

static uint32_t IMA_TemplateDataIma_ReadFile(ImaEvent *imaEvent,	/* freed by caller */
					     int *endOfFile,
					     FILE *inFile,
					     int littleEndian)
{
    int 	rc = 0;
    size_t 	readSize;
    uint8_t 	fileDataHash[SHA1_DIGEST_SIZE];		/* IMA hard coded to SHA-1 */
    uint32_t 	fileNameLengthIbo;			/* ima log byte order */
    uint32_t 	fileNameLength;				/* host byte order */

    /* read the fileDataHash digest, this is hard coded to SHA-1 */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&fileDataHash,
			 sizeof(fileDataHash), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_TemplateDataIma_ReadFile: "
		       "could not read fileDataHash, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the IMA name length */
    if ((rc == 0) && !(*endOfFile)) {
	readSize = fread(&fileNameLengthIbo,
			 sizeof(fileNameLength), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_TemplateDataIma_ReadFile: "
		       "could not read fileNameLength, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	fileNameLength = IMA_Uint32_Convert((uint8_t *)&fileNameLengthIbo, littleEndian);
	/* should check for addition overflowing a uint32_t */
	if (fileNameLength > (0xffffffff - (uint32_t)(sizeof(fileDataHash) + sizeof(fileNameLength)))) {
	    printf("ERROR: IMA_TemplateDataIma_ReadFile: file name length too big: %u\n",
		   fileNameLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	/* addition is safe because of above check */
	imaEvent->template_data_len = sizeof(fileDataHash) + sizeof(fileNameLength) + fileNameLength;
    }
    /* bounds check the template data length */
    if ((rc == 0) && !(*endOfFile)) {
	if (imaEvent->template_data_len > TCG_TEMPLATE_DATA_LEN_MAX) {
	    printf("ERROR: IMA_TemplateDataIma_ReadFile: template data length too big: %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if ((rc == 0) && !(*endOfFile)) {
	imaEvent->template_data = malloc(imaEvent->template_data_len);
	if (imaEvent->template_data == NULL) {
	    printf("ERROR: IMA_TemplateDataIma_ReadFile: "
		   "could not allocate template data, size %u\n",
		   imaEvent->template_data_len);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* copy results to template_data */
    if ((rc == 0) && !(*endOfFile)) {
	/* copy file data hash */
	/* ignore VS warning, template_data_len is calculated above for malloc, no buffer overrun */
	memcpy(imaEvent->template_data, fileDataHash, sizeof(fileDataHash));
	/* copy file name length */
	memcpy(imaEvent->template_data + sizeof(fileDataHash),
	       &fileNameLengthIbo, sizeof(fileNameLength));
	/* read and copy the file name */
	readSize = fread(imaEvent->template_data + sizeof(fileDataHash) + sizeof(fileNameLength),
			 fileNameLength, 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("ERROR: IMA_TemplateDataIma_ReadFile: "
		       "could not read fileNameLength, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    return rc;
}
 
/* IMA_Event_ReadBuffer()  reads one IMA event from a buffer.

   This is typically used at the server, reading from a client connection.

   Although the raw IMA event log 'ima' template does not have a template data length, this function
   at the server assumes it has been inserted by the client.

   If getTemplate is TRUE, the template data is copied to a malloced imaEvent->template_data.  If
   FALSE, template data is skipped. FALSE is used for the first pass, where the template data is not
   needed until the hash is validated.

*/

uint32_t IMA_Event_ReadBuffer(ImaEvent *imaEvent,	/* freed by caller */
			      size_t *length,
			      uint8_t **buffer,
			      int *endOfBuffer,
			      int littleEndian,
			      int getTemplate)
{
    int rc = 0;

    imaEvent->template_data = NULL;		/* for free */
    if (*length == 0) {
	*endOfBuffer = 1;
    }
    else {
	/* read the IMA pcr index */
	if (rc == 0) {
	    rc = IMA_Uint32_Unmarshal(&imaEvent->pcrIndex, buffer, length, littleEndian);
	}
	/* sanity check the PCR index */
	if (rc == 0) {
	    if (imaEvent->pcrIndex != IMA_PCR) {
		printf("ERROR: IMA_Event_ReadBuffer: PCR index %u not PCR %u\n",
		       IMA_PCR, imaEvent->pcrIndex);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
	/* read the IMA digest, this is hard coded to SHA-1 */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < sizeof(((ImaEvent *)NULL)->digest)) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for IMA digest\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		memcpy(&(imaEvent->digest), *buffer, sizeof(((ImaEvent *)NULL)->digest));
		*buffer += sizeof(((ImaEvent *)NULL)->digest);
		*length -= sizeof(((ImaEvent *)NULL)->digest);
	    }
	}
	/* read the IMA name length */
	if (rc == 0) {
	    rc = IMA_Uint32_Unmarshal(&imaEvent->name_len, buffer, length, littleEndian);
	}
	/* read the template name */
	if (rc == 0) {
	    /* bounds check the name length */
	    if (imaEvent->name_len > TCG_EVENT_NAME_LEN_MAX) {
		printf("ERROR: IMA_Event_ReadBuffer: Error, template name length too big: %u\n",
		       imaEvent->name_len);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else if (*length < imaEvent->name_len) {
		printf("ERROR: IMA_Event_ReadBuffer: buffer too small for template name\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		/* nul terminate first */
		memset(imaEvent->name, 0, sizeof(((ImaEvent *)NULL)->name));
		memcpy(&(imaEvent->name), *buffer, imaEvent->name_len);
		*buffer += imaEvent->name_len;
		*length -= imaEvent->name_len;
	    }
	}
	/* record the template name as an int */
	if (rc == 0) {
	    IMA_Event_ParseName(imaEvent);
	}
	/* read the template data length */
	if (rc == 0) {
	    rc = IMA_Uint32_Unmarshal(&imaEvent->template_data_len, buffer, length, littleEndian);
	}
	/* allocate for the template data */
	if (rc == 0) {
	    if (getTemplate) {
		/* bounds check the template data length */
		if (imaEvent->template_data_len > TCG_TEMPLATE_DATA_LEN_MAX) {
		    printf("ERROR: IMA_Event_ReadBuffer: template data length too big: %u\n",
			   imaEvent->template_data_len);
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
		else if (*length < imaEvent->template_data_len) {
		    printf("ERROR: IMA_Event_ReadBuffer: buffer too small for template data\n");
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
		else {
		    if (rc == 0) {
			imaEvent->template_data = malloc(imaEvent->template_data_len);
			if (imaEvent->template_data == NULL) {
			    printf("ERROR: IMA_Event_ReadBuffer: "
				   "could not allocate template data, size %u\n",
				   imaEvent->template_data_len);
			    rc = TSS_RC_OUT_OF_MEMORY;
			}
		    }
		    if (rc == 0) {
			memcpy(imaEvent->template_data, *buffer, imaEvent->template_data_len);
		    }
		}
	    }
	    /* move the buffer even if getTemplate is false */
	    if (rc == 0) {
		*buffer += imaEvent->template_data_len;
		*length -= imaEvent->template_data_len;
	    }
	}
    }
    return rc;
}

/* IMA_TemplateName_Parse() parses the template name and registers the template data parsing and
   tracing callbacks */

static uint32_t IMA_TemplateName_Parse(TemplateDataParseFunction_t templateDataParseFunctions[],
				       TemplateDataTraceFunction_t templateDataTraceFunctions[],
				       size_t templateDataParseFunctionsSize,
				       ImaEvent *imaEvent)
{
    uint32_t 	rc = 0;
    size_t	i;

    /* initialize all the function pointers to NULL */
    for (i = 0 ; (rc == 0) && (i < templateDataParseFunctionsSize) ; i++) {
	templateDataParseFunctions[i] = NULL;
	templateDataTraceFunctions[i] = NULL;
    }
    /* parse the name into the callback structure */
    if (rc == 0) {
	switch (imaEvent->nameInt) {
	    /* these are the pre-defined formats */
	  case IMA_FORMAT_IMA_NG:
	    /* d-ng | n-ng */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNG;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNG;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    break;
	  case IMA_FORMAT_IMA_NGV2:
	    /* d-ng | n-ngv2 */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNGV2;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNGV2;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    break;
	  case IMA_FORMAT_IMA_SIG:
	    /* d-ng | n-ng | sig */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNG;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;
	    templateDataParseFunctions[2] = (TemplateDataParseFunction_t)IMA_ParseSIG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNG;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    templateDataTraceFunctions[2] = (TemplateDataTraceFunction_t)IMA_TraceSIG;
	    break;
	  case IMA_FORMAT_IMA_SIGV2:
	    /* d-ngv2 | n-ng | sig */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNGV2;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;
	    templateDataParseFunctions[2] = (TemplateDataParseFunction_t)IMA_ParseSIG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNGV2;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    templateDataTraceFunctions[2] = (TemplateDataTraceFunction_t)IMA_TraceSIG;
	    break;
	  case IMA_FORMAT_IMA:
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseD;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceD;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    break;
	  case IMA_FORMAT_IMA_MODSIG:
	    /* d-ng | n-ng | sig | d-modsig | modsig */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNG;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;
	    templateDataParseFunctions[2] = (TemplateDataParseFunction_t)IMA_ParseSIG;
	    templateDataParseFunctions[3] = (TemplateDataParseFunction_t)IMA_ParseDMODSIG;
	    templateDataParseFunctions[4] = (TemplateDataParseFunction_t)IMA_ParseMODSIG;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNG;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    templateDataTraceFunctions[2] = (TemplateDataTraceFunction_t)IMA_TraceSIG;
	    templateDataTraceFunctions[3] = (TemplateDataTraceFunction_t)IMA_TraceDMODSIG;
	    templateDataTraceFunctions[4] = (TemplateDataTraceFunction_t)IMA_TraceMODSIG;
	    break;
	  case IMA_FORMAT_IMA_BUF:
	    /* d-ng | n-ng | buf */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNG;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;
	    templateDataParseFunctions[2] = (TemplateDataParseFunction_t)IMA_ParseBUF;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNG;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    templateDataTraceFunctions[2] = (TemplateDataTraceFunction_t)IMA_TraceBUF;
	    break;
	  case IMA_FORMAT_EVM_SIG:
	    /* d-ng | n-ng | evmsig | xattrnames | xattrlengths | xattrvalues |
	       iuid | igid | imode */
	    templateDataParseFunctions[0] = (TemplateDataParseFunction_t)IMA_ParseDNG;
	    templateDataParseFunctions[1] = (TemplateDataParseFunction_t)IMA_ParseNNG;
	    templateDataParseFunctions[2] = (TemplateDataParseFunction_t)IMA_ParseSIG;
	    templateDataParseFunctions[3] = (TemplateDataParseFunction_t)IMA_ParseXATTRNAMES;
	    templateDataParseFunctions[4] = (TemplateDataParseFunction_t)IMA_ParseXATTRLENGTHS;
	    templateDataParseFunctions[5] = (TemplateDataParseFunction_t)IMA_ParseXATTRVALUES;
	    templateDataParseFunctions[6] = (TemplateDataParseFunction_t)IMA_ParseIUID;
	    templateDataParseFunctions[7] = (TemplateDataParseFunction_t)IMA_ParseIGID;
	    templateDataParseFunctions[8] = (TemplateDataParseFunction_t)IMA_ParseIMODE;

	    templateDataTraceFunctions[0] = (TemplateDataTraceFunction_t)IMA_TraceDNG;
	    templateDataTraceFunctions[1] = (TemplateDataTraceFunction_t)IMA_TraceNNG;
	    templateDataTraceFunctions[2] = (TemplateDataTraceFunction_t)IMA_TraceSIG;
	    templateDataTraceFunctions[3] = (TemplateDataTraceFunction_t)IMA_TraceXATTRNAMES;
	    templateDataTraceFunctions[4] = (TemplateDataTraceFunction_t)IMA_TraceXATTRLENGTHS;
	    templateDataTraceFunctions[5] = (TemplateDataTraceFunction_t)IMA_TraceXATTRVALUES;
	    templateDataTraceFunctions[6] = (TemplateDataTraceFunction_t)IMA_TraceIUID;
	    templateDataTraceFunctions[7] = (TemplateDataTraceFunction_t)IMA_TraceIGID;
	    templateDataTraceFunctions[8] = (TemplateDataTraceFunction_t)IMA_TraceIMODE;
	    break;
	    /* these are potentially the custom templates */
	  default:
	    rc = IMA_TemplateName_ParseCustom(templateDataParseFunctions,
					      templateDataTraceFunctions,
					      templateDataParseFunctionsSize,
					      imaEvent);
	}
    }
    return rc;
}

/* the mapping between a format string and the template data parse function */

typedef struct {
    const char *formatString;
    TemplateDataParseFunction_t parseFunction;
    TemplateDataTraceFunction_t traceFunction;
} ImaFormatMap; 

static ImaFormatMap imaFormatMap[] = {
    {"d",
     (TemplateDataParseFunction_t)IMA_ParseD,
     (TemplateDataTraceFunction_t)IMA_TraceD},
    {"n",
     (TemplateDataParseFunction_t)IMA_ParseNNG,
     (TemplateDataTraceFunction_t)IMA_TraceNNG},
    {"d-ng",
     (TemplateDataParseFunction_t)IMA_ParseDNG,
     (TemplateDataTraceFunction_t)IMA_TraceDNG},
    {"d-ngv2",
     (TemplateDataParseFunction_t)IMA_ParseDNGV2,
     (TemplateDataTraceFunction_t)IMA_TraceDNGV2},
    {"n-ng",
     (TemplateDataParseFunction_t)IMA_ParseNNG,
     (TemplateDataTraceFunction_t)IMA_TraceNNG},
    {"sig",
     (TemplateDataParseFunction_t)IMA_ParseSIG,
     (TemplateDataTraceFunction_t)IMA_TraceSIG},
    {"d-modsig",
      (TemplateDataParseFunction_t)IMA_ParseDMODSIG,
      (TemplateDataTraceFunction_t)IMA_TraceDMODSIG},
    {"modsig",
     (TemplateDataParseFunction_t)IMA_ParseMODSIG,
     (TemplateDataTraceFunction_t)IMA_TraceMODSIG},
    {"buf",
     (TemplateDataParseFunction_t)IMA_ParseBUF,
     (TemplateDataTraceFunction_t)IMA_TraceBUF},
    {"xattrnames",
     (TemplateDataParseFunction_t)IMA_ParseXATTRNAMES,
     (TemplateDataTraceFunction_t)IMA_TraceXATTRNAMES},
    {"xattrlengths",
     (TemplateDataParseFunction_t)IMA_ParseXATTRLENGTHS,
     (TemplateDataTraceFunction_t)IMA_TraceXATTRLENGTHS},
    {" xattrvalues",
     (TemplateDataParseFunction_t)IMA_ParseXATTRVALUES,
     (TemplateDataTraceFunction_t)IMA_TraceXATTRVALUES},
    {"iuid",
     (TemplateDataParseFunction_t)IMA_ParseIUID,
     (TemplateDataTraceFunction_t)IMA_TraceIUID},
    {"igid",
     (TemplateDataParseFunction_t)IMA_ParseIGID,
     (TemplateDataTraceFunction_t)IMA_TraceIGID},
    {"imode",
     (TemplateDataParseFunction_t)IMA_ParseIMODE,
     (TemplateDataTraceFunction_t)IMA_TraceIMODE}
};

/* IMA_TemplateName_ParseCustom() parses the template custom (not built-in) names and registers the
   template data parsing and tracing callbacks */

static uint32_t
IMA_TemplateName_ParseCustom(TemplateDataParseFunction_t templateDataParseFunctions[],
			     TemplateDataTraceFunction_t templateDataTraceFunctions[],
			     size_t templateDataParseFunctionsSize,
			     ImaEvent *imaEvent)
{
    uint32_t 	rc = 0;
    size_t	i;		/* index into templateDataParseFunctions table */
    size_t	j;		/* index into imaFormatMap table */
    char 	*startName;
    char	*endName;
    char 	templateName[TCG_EVENT_NAME_LEN_MAX + 1];	/* one | separated item with nul */

    /* parse the custom templates, strcpy is safe because the reader did the bounds check */
    strcpy(templateName, imaEvent->name);	/* modify'able */
    startName = templateName;

    for (i = 0 ; (rc == 0) && (i < templateDataParseFunctionsSize) ; i++) {
	endName = strchr(startName, '|');
	if (endName != NULL) {	/* found a | character */
	    *endName = '\0';	/* nul terminate the next format string */
	}
	printf("item %lu : %s\n", (unsigned long)i, startName);
	/* search the table for the format string */
	for (j = 0 ; j < (sizeof(imaFormatMap) / sizeof(ImaFormatMap)) ; j++) {
	    int irc;
	    irc = strcmp(startName, imaFormatMap[j].formatString);
	    if (irc == 0) {
		templateDataParseFunctions[i] = imaFormatMap[j].parseFunction;
		templateDataTraceFunctions[i] = imaFormatMap[j].traceFunction;
	    }
	}
	/* if no format string found */
	if (templateDataParseFunctions[i] == NULL) {
	    printf("ERROR: IMA_TemplateName_ParseCustom: unknown format string %s\n",
		   startName);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
	/* if found an item, move the pointer */
	if (rc == 0) {
	    startName = endName + 1;
	}
	if (endName == NULL) {	/* no | character, last entry */
	    break;
	}
    }
    return rc;
}

/*
  template data parsing callbacks
*/

/* IMA_ParseD() parses a d : digest (no length or algorithm) */

static uint32_t IMA_ParseD(ImaTemplateData	*imaTemplateData,
			   uint8_t 		**buffer,
			   size_t 		*length,
			   int 			littleEndian)
{
    uint32_t 	rc = 0;
    littleEndian = littleEndian;	/* unised */
    /* fileDataHash */
    if (rc == 0) {
	/* bounds check the length */
	if (*length < SHA1_DIGEST_SIZE) {
	    printf("ERROR: IMA_ParseD: buffer too small for file data hash\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    imaTemplateData->imaTemplateDNG.fileDataHashLength = SHA1_DIGEST_SIZE;
	    memcpy(&(imaTemplateData->imaTemplateDNG.fileDataHash), *buffer, SHA1_DIGEST_SIZE);
	    *buffer += SHA1_DIGEST_SIZE;
	    *length -= SHA1_DIGEST_SIZE;
	}
    }
    return rc;
}

/* IMA_ParseDNG parses a d-ng : hash length + hash algorithm string + digest

   The digest is a file data hash.
 */

static uint32_t IMA_ParseDNG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian)
{
    uint32_t 	rc = 0;
    size_t 	hashAlgSize;
    /* read the hash length, algorithm + hash */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateDNG.hashLength,
				  buffer, length, littleEndian);
    }
    /* read the hash algorithm, nul terminated string */
    if (rc == 0) {
    	/* NUL terminate first */
	memset(imaTemplateData->imaTemplateDNG.hashAlg, 0,
	       sizeof(((ImaTemplateData *)NULL)->imaTemplateDNG.hashAlg));
	rc = IMA_Strn2cpy(imaTemplateData->imaTemplateDNG.hashAlg, *buffer,
			  sizeof(((ImaTemplateData *)NULL)->imaTemplateDNG.hashAlg),	/* destLength */
			  imaTemplateData->imaTemplateDNG.hashLength);			/* srcLength */
	if (rc != 0) {
	    printf("ERROR: IMA_ParseDNG: buffer too small for hash algorithm\n"
		   "\tor hash algorithm exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    hashAlgSize = strlen(imaTemplateData->imaTemplateDNG.hashAlg) + 1;
	    *buffer += hashAlgSize;
	    *length -= hashAlgSize;
	}
    }
    /* fileDataHashLength */
    if (rc == 0) {
	if (strcmp(imaTemplateData->imaTemplateDNG.hashAlg, "sha1:") == 0) {
	    imaTemplateData->imaTemplateDNG.fileDataHashLength = SHA1_DIGEST_SIZE;
	    imaTemplateData->imaTemplateDNG.hashAlgId = TPM_ALG_SHA1;
	}
	else if (strcmp(imaTemplateData->imaTemplateDNG.hashAlg, "sha256:") == 0) {
	    imaTemplateData->imaTemplateDNG.fileDataHashLength = SHA256_DIGEST_SIZE;
	    imaTemplateData->imaTemplateDNG.hashAlgId = TPM_ALG_SHA256;
	}
	else {
	    printf("ERROR: IMA_ParseDNG: Unknown file data hash algorithm: %s\n",
		   imaTemplateData->imaTemplateDNG.hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* consistency check hashLength vs contents */
    if (rc == 0) {
	if ((hashAlgSize + imaTemplateData->imaTemplateDNG.fileDataHashLength) !=
	    imaTemplateData->imaTemplateDNG.hashLength) {
	    printf("ERROR: IMA_ParseDNG: "
		   "hashLength %u inconsistent with hashAlgSize %lu and fileDataHashLength %u\n",
		   imaTemplateData->imaTemplateDNG.hashLength, (unsigned long)hashAlgSize,
		   imaTemplateData->imaTemplateDNG.fileDataHashLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* fileDataHash */
    if (rc == 0) {
	/* bounds check the length */
	if (*length < imaTemplateData->imaTemplateDNG.fileDataHashLength) {
	    printf("ERROR: IMA_ParseDNG: buffer too small for file data hash\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateDNG.fileDataHashLength >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateDNG.fileDataHash)) {
	    printf("ERROR: IMA_ParseDNG: "
		   "file data hash length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	} 
	else {
	    memcpy(&(imaTemplateData->imaTemplateDNG.fileDataHash), *buffer,
		   imaTemplateData->imaTemplateDNG.fileDataHashLength);
	    *buffer += imaTemplateData->imaTemplateDNG.fileDataHashLength;
	    *length -= imaTemplateData->imaTemplateDNG.fileDataHashLength;
#if 0
	    TSS_PrintAll("IMA_ParseDNG: file data hash",
			 imaTemplateData->imaTemplateDNG.fileDataHash,
			 imaTemplateData->imaTemplateDNG.fileDataHashLength);
#endif
	}
    }
    return rc;
}

/* IMA_ParseDNGV2 parses a d-ngv2 : length + prefix + hash algorithm + hash

   The digest is a file data hash.
*/

static uint32_t IMA_ParseDNGV2(ImaTemplateData	*imaTemplateData,
			       uint8_t 		**buffer,
			       size_t 		*length,
			       int 		littleEndian)
{
    uint32_t 	rc = 0;
    size_t 	hashAlgSize;
    size_t 	prefixSize;

    /* read the length, prefix + algorithm + hash */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateDNGV2.hashLength,
				  buffer, length, littleEndian);
    }
    /* read the prefix, : terminated string */
    if (rc == 0) {
    	/* NUL terminate first */
	memset(imaTemplateData->imaTemplateDNGV2.prefix, 0,
	       sizeof(((ImaTemplateData *)NULL)->imaTemplateDNGV2.prefix));
	rc = IMA_Strc2cpy(imaTemplateData->imaTemplateDNGV2.prefix, *buffer,
			  sizeof(((ImaTemplateData *)NULL)->imaTemplateDNGV2.prefix),
			  imaTemplateData->imaTemplateDNGV2.hashLength);
	if (rc != 0) {
	    printf("ERROR: IMA_ParseDNGV2: buffer too small for prefix\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    prefixSize = strlen(imaTemplateData->imaTemplateDNGV2.prefix);
	    *buffer += prefixSize;
	    *length -= prefixSize;
	}
    }
    /* read the hash algorithm, nul terminated string */
    if (rc == 0) {
    	/* NUL terminate first */
	memset(imaTemplateData->imaTemplateDNGV2.hashAlg, 0,
	       sizeof(((ImaTemplateData *)NULL)->imaTemplateDNGV2.hashAlg));
	rc = IMA_Strn2cpy(imaTemplateData->imaTemplateDNGV2.hashAlg, *buffer,
			  /* destLength */
			  sizeof(((ImaTemplateData *)NULL)->imaTemplateDNGV2.hashAlg),
			  /* srcLength */
			  imaTemplateData->imaTemplateDNGV2.hashLength - prefixSize);
	if (rc != 0) {
	    printf("ERROR: IMA_ParseDNGV2: buffer too small for hash algorithm\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    hashAlgSize = strlen(imaTemplateData->imaTemplateDNGV2.hashAlg) + 1;
	    *buffer += hashAlgSize;
	    *length -= hashAlgSize;
	}
    }
    /* fileDataHashLength */
    if (rc == 0) {
	if (strcmp(imaTemplateData->imaTemplateDNGV2.hashAlg, "sha1:") == 0) {
	    imaTemplateData->imaTemplateDNGV2.fileDataHashLength = SHA1_DIGEST_SIZE;
	    imaTemplateData->imaTemplateDNGV2.hashAlgId = TPM_ALG_SHA1;
	}
	else if (strcmp(imaTemplateData->imaTemplateDNGV2.hashAlg, "sha256:") == 0) {
	    imaTemplateData->imaTemplateDNGV2.fileDataHashLength = SHA256_DIGEST_SIZE;
	    imaTemplateData->imaTemplateDNGV2.hashAlgId = TPM_ALG_SHA256;
	}
	else {
	    printf("ERROR: IMA_ParseDNGV2: Unknown file data hash algorithm: %s\n",
		   imaTemplateData->imaTemplateDNGV2.hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* consistency check hashLength vs contents */
    if (rc == 0) {
	if ((prefixSize + hashAlgSize + imaTemplateData->imaTemplateDNGV2.fileDataHashLength) !=
	    imaTemplateData->imaTemplateDNGV2.hashLength) {
	    printf("ERROR: IMA_ParseDNGV2: "
		   "hashLength %u inconsistent with prefixSize %lu hashAlgSize %lu "
		   "and fileDataHashLength %u\n",
		   imaTemplateData->imaTemplateDNGV2.hashLength,
		   (unsigned long)prefixSize,
		   (unsigned long)hashAlgSize,
		   imaTemplateData->imaTemplateDNGV2.fileDataHashLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* fileDataHash */
    if (rc == 0) {
	/* bounds check the length */
	if (*length < imaTemplateData->imaTemplateDNGV2.fileDataHashLength) {
	    printf("ERROR: IMA_ParseDNGV2: buffer too small for file data hash\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateDNGV2.fileDataHashLength >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateDNGV2.fileDataHash)) {
	    printf("ERROR: IMA_ParseDNGV2: "
		   "file data hash length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	} 
	else {
	    memcpy(&(imaTemplateData->imaTemplateDNGV2.fileDataHash), *buffer,
		   imaTemplateData->imaTemplateDNGV2.fileDataHashLength);
	    *buffer += imaTemplateData->imaTemplateDNGV2.fileDataHashLength;
	    *length -= imaTemplateData->imaTemplateDNGV2.fileDataHashLength;
#if 0
	    TSS_PrintAll("IMA_ParseDNGV2: file data hash",
			 imaTemplateData->imaTemplateDNGV2.fileDataHash,
			 imaTemplateData->imaTemplateDNGV2.fileDataHashLength);
#endif
	}
    }
    return rc;
}

/* IMA_ParseNNG() parses a n-ng : length + filename */

static uint32_t IMA_ParseNNG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian)
{
    uint32_t 	rc = 0;
    /* fileNameLength (length includes the nul terminator) */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateNNG.fileNameLength,
				  buffer, length, littleEndian);
    }
    /* fileName */
    if (rc == 0) {
	/* bounds check the length */
	if (*length < imaTemplateData->imaTemplateNNG.fileNameLength) {
	    printf("ERROR: IMA_ParseNNG: buffer too small for file name\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	/* leave one byte for the nul terminator */
	else if (imaTemplateData->imaTemplateNNG.fileNameLength >
		 (sizeof(imaTemplateData->imaTemplateNNG.fileName)-1)) {
	    printf("ERROR: IMA_ParseNNG: file name length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else {
	    memcpy(&(imaTemplateData->imaTemplateNNG.fileName), *buffer,
		   imaTemplateData->imaTemplateNNG.fileNameLength);
	    /* ima template does not nul terminate the file name */
	    imaTemplateData->imaTemplateNNG.fileName[imaTemplateData->imaTemplateNNG.fileNameLength] = '\0';
	    *buffer += imaTemplateData->imaTemplateNNG.fileNameLength;
	    *length -= imaTemplateData->imaTemplateNNG.fileNameLength;
	}
    }
    return rc;
}

/* IMA_ParseSIG() parses a sig : signature header + signature */

static uint32_t IMA_ParseSIG(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian)
{
    uint32_t 	rc = 0;
    /* sigLength */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateSIG.sigLength,
				  buffer, length, littleEndian);
    }
    /* sigHeader - only parsed if its length is not zero */
    if (imaTemplateData->imaTemplateSIG.sigLength != 0) {
	if (rc == 0) {
	    imaTemplateData->imaTemplateSIG.sigHeaderLength =
		sizeof((ImaTemplateData *)NULL)->imaTemplateSIG.sigHeader;
	    /* bounds check the length */
	    if (*length < imaTemplateData->imaTemplateSIG.sigHeaderLength) {
		printf("ERROR: IMA_ParseSIG: "
		       "buffer too small for signature header\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		memcpy(&(imaTemplateData->imaTemplateSIG.sigHeader), *buffer,
		       imaTemplateData->imaTemplateSIG.sigHeaderLength);
		*buffer += imaTemplateData->imaTemplateSIG.sigHeaderLength;
		*length -= imaTemplateData->imaTemplateSIG.sigHeaderLength;
	    }
	}
	/* get signature length from last two bytes */
	if (rc == 0) {
	    /* magic number for offset: type(1) version(1) hash alg (1) pubkey id (4) */
	    imaTemplateData->imaTemplateSIG.signatureSize =
		ntohs(*(uint16_t *)(imaTemplateData->imaTemplateSIG.sigHeader + 7));
	}
	/* consistency check signature header contents */
	if (rc == 0) {
	    int goodHashAlgo = (((imaTemplateData->imaTemplateSIG.sigHeader[2] == HASH_ALGO_SHA1) &&
				 (imaTemplateData->imaTemplateDNG.hashAlgId == TPM_ALG_SHA1)) ||
				((imaTemplateData->imaTemplateSIG.sigHeader[2] == HASH_ALGO_SHA256) &&
				 (imaTemplateData->imaTemplateDNG.hashAlgId == TPM_ALG_SHA256)) ||
				/* might have sig without dng */
				(imaTemplateData->imaTemplateDNG.hashAlgId == TPM_ALG_NULL));
	    /* xattr type */
	    if (
		(imaTemplateData->imaTemplateSIG.sigHeader[1] != 2) ||		/* [1] version */
		!goodHashAlgo				/* [2] hash algorithm */
		/* [3]-[6] are the public key fingerprint.  Any value is legal. */
		/* [7][8] sig size cannot be checked, sig alg is not in log */
		) {
		printf("ERROR: IMA_ParseSIG: invalid sigHeader %02x %02x\n",
		       imaTemplateData->imaTemplateSIG.sigHeader[0],
		       imaTemplateData->imaTemplateSIG.sigHeader[1]);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
	/* signature */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < imaTemplateData->imaTemplateSIG.signatureSize) {
		printf("ERROR: IMA_ParseSIG: "
		       "buffer too small for signature \n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    /* sanity check the signatureSize against the sigLength */
	    else if (imaTemplateData->imaTemplateSIG.sigLength !=
		     (sizeof((ImaTemplateData *)NULL)->imaTemplateSIG.sigHeader +
		      imaTemplateData->imaTemplateSIG.signatureSize)) {
		printf("ERROR: IMA_ParseSIG: "
		       "sigLength inconsistent with signatureSize\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		memcpy(&(imaTemplateData->imaTemplateSIG.signature), *buffer,
		       imaTemplateData->imaTemplateSIG.signatureSize);
		*buffer += imaTemplateData->imaTemplateSIG.signatureSize;
		*length -= imaTemplateData->imaTemplateSIG.signatureSize;
#if 0
		TSS_PrintAll("IMA_ParseSIG: file data hash",
			     imaTemplateData->imaTemplateSIG.signature,
			     imaTemplateData->imaTemplateSIG.signatureSize);

#endif
	    }
	}
    }
    return rc;
}

/* IMA_ParseDMODSIG parses a d-ng : hash length + hash algorithm string + digest

   The digest is a file data hash omitting the appended modsig signature.

   NOTE: This is currently thre same as IMA_ParseDNG but may have different processing in the
   future.
*/

static uint32_t IMA_ParseDMODSIG(ImaTemplateData	*imaTemplateData,
				 uint8_t 		**buffer,
				 size_t 		*length,
				 int 			littleEndian)
{
    uint32_t 	rc = 0;
    size_t 	hashAlgSize;

    /* read the hash length, algorithm + hash */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateDMODSIG.dModSigHashLength,
				  buffer, length, littleEndian);
    }
    /* FIXME is zero length an error? */
    if (imaTemplateData->imaTemplateDMODSIG.dModSigHashLength != 0) {

	/* read the hash algorithm, nul terminated string */
	if (rc == 0) {
	    /* NUL terminate first */
	    memset(imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg, 0,
		   sizeof(((ImaTemplateData *)NULL)->imaTemplateDMODSIG.dModSigHashAlgId));
	    rc = IMA_Strn2cpy(imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg, *buffer,
			      /* destLength */
			      sizeof(((ImaTemplateData *)NULL)->imaTemplateDMODSIG.dModSigHashAlg),
			      /* srcLength */
			      imaTemplateData->imaTemplateDMODSIG.dModSigHashLength);
	    if (rc != 0) {
		printf("ERROR: IMA_ParseDMODSIG: buffer too small for hash algorithm\n"
		       "\tor hash algorithm exceeds maximum size\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		hashAlgSize = strlen(imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg) + 1;
		*buffer += hashAlgSize;
		*length -= hashAlgSize;
	    }
	}
	/* dModSigFileDataHashLength */
	if (rc == 0) {
	    if (strcmp(imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg, "sha1:") == 0) {
		imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength = SHA1_DIGEST_SIZE;
		imaTemplateData->imaTemplateDMODSIG.dModSigHashAlgId = TPM_ALG_SHA1;
	    }
	    else if (strcmp(imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg, "sha256:") == 0) {
		imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength = SHA256_DIGEST_SIZE;
		imaTemplateData->imaTemplateDMODSIG.dModSigHashAlgId = TPM_ALG_SHA256;
	    }
	    else {
		printf("ERROR: IMA_ParseDMODSIG: Unknown file data hash algorithm: %s\n",
		       imaTemplateData->imaTemplateDMODSIG.dModSigHashAlg);
		rc = TSS_RC_BAD_HASH_ALGORITHM;
	    }
	}
	/* consistency check dModSigFileDataHashLength vs contents */
	if (rc == 0) {
	    if ((hashAlgSize + imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength) !=
		imaTemplateData->imaTemplateDMODSIG.dModSigHashLength) {
		printf("ERROR: IMA_ParseDMODSIG: "
		       "dModSigFileDataHashLength %u inconsistent with hashAlgSize %lu "
		       "and dModSigFileDataHashLength %u\n",
		       imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength,
		       (unsigned long)hashAlgSize,
		       imaTemplateData->imaTemplateDMODSIG.dModSigHashLength);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* dModSigFileDataHashLength */
	if (rc == 0) {
	    /* bounds check the length */
	    if (*length < imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength ) {
		printf("ERROR: IMA_ParseDMODSIG: buffer too small for file data hash\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else if (imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength >
		     sizeof(((ImaTemplateData *)NULL)->imaTemplateDMODSIG.dModSigFileDataHash)) {
		printf("ERROR: IMA_ParseDMODSIG: "
		       "file data hash length exceeds maximum size\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    } 
	    else {
		memcpy(&(imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHash),
		       *buffer, imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength);
		*buffer += imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength ;
		*length -= imaTemplateData->imaTemplateDMODSIG.dModSigFileDataHashLength ;
	    }
	}
    }
    return rc;
}

/* IMA_ParseMODSIG parses a modsig : 4 byte length + DER encoded CMS document, RFC 5652 */

static uint32_t IMA_ParseMODSIG(ImaTemplateData	*imaTemplateData,
				uint8_t 	**buffer,
				size_t 		*length,
				int 		littleEndian)
{
    uint32_t 	rc = 0;

    /* read the length */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateMODSIG.modSigLength,
				  buffer, length, littleEndian);
    }
    /* read the DER */
    if (rc == 0) {
	/* bounds check the length */
	if (*length  < imaTemplateData->imaTemplateMODSIG.modSigLength) {
	    printf("ERROR: IMA_ParseMODSIG: buffer too small for modSig data\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateMODSIG.modSigLength >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateMODSIG.modSigData)) {
	    printf("ERROR: IMA_ParseMODSIG: "
		   "modSigData length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	} 
	else {
	    memcpy(&(imaTemplateData->imaTemplateMODSIG.modSigData), *buffer,
		   imaTemplateData->imaTemplateMODSIG.modSigLength);
	    *buffer += imaTemplateData->imaTemplateMODSIG.modSigLength;
	    *length -= imaTemplateData->imaTemplateMODSIG.modSigLength;
	}
    }
    return rc;
}

/* IMA_ParseBUF parses a modsig : 4 byte length + DER encoded CMS document, RFC 5652 */

static uint32_t IMA_ParseBUF(ImaTemplateData	*imaTemplateData,
			     uint8_t 		**buffer,
			     size_t 		*length,
			     int 		littleEndian)
{
    uint32_t 	rc = 0;

    /* read the length */
    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateBUF.bufLength,
				  buffer, length, littleEndian);
    }
    /* read the DER */
    if (rc == 0) {
	/* bounds check the length */
	if (*length  < imaTemplateData->imaTemplateBUF.bufLength) {
	    printf("ERROR: IMA_ParseBUF: buffer too small for buf data\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateBUF.bufLength >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateBUF.bufData)) {
	    printf("ERROR: IMA_ParseBUF: "
		   "bufData length exceeds maximum size\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	} 
	else {
	    memcpy(&(imaTemplateData->imaTemplateBUF.bufData), *buffer,
		   imaTemplateData->imaTemplateBUF.bufLength);
	    *buffer += imaTemplateData->imaTemplateBUF.bufLength;
	    *length -= imaTemplateData->imaTemplateBUF.bufLength;
	}
    }
    return rc;
}

/* IMA_ParseXATTRNAMESz parses an xattrnames field */

static uint32_t IMA_ParseXATTRNAMES(ImaTemplateData	*imaTemplateData,
				    uint8_t 		**buffer,
				    size_t 		*length,
				    int 		littleEndian)
{
    uint32_t 	rc = 0;
    size_t	i;
    size_t 	xattrNamesSize;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateXattrs.xattrNamesLength,
				  buffer, length, littleEndian);
    }
    if (imaTemplateData->imaTemplateXattrs.xattrNamesLength > 0) {
	if (rc == 0) {
	    /* NUL terminate first */
	    memset(imaTemplateData->imaTemplateXattrs.xattrNames, 0,
		   sizeof(((ImaTemplateData *)NULL)->imaTemplateXattrs.xattrNames));
	    /* copy nul terminated xattrnames string */
	    rc = IMA_Strn2cpy(imaTemplateData->imaTemplateXattrs.xattrNames, *buffer,
			      /* destLength */
			      sizeof(((ImaTemplateData *)NULL)->imaTemplateXattrs.xattrNames),
			      /* srcLength */
			      imaTemplateData->imaTemplateXattrs.xattrNamesLength);
	    if (rc != 0) {
		printf("ERROR: IMA_ParseXATTRNAMES: buffer too small for xattrNames\n"
		       "\tor xattrNames exceeds maximum size\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	    else {
		/* add one to strlen for nul terminator */
		xattrNamesSize = strlen(imaTemplateData->imaTemplateXattrs.xattrNames) + 1;
		*buffer += xattrNamesSize;
		*length -= xattrNamesSize;
	    }
	}
	/* verify length of xattrnames against the string length */
	if (rc == 0) {
	    if (xattrNamesSize != imaTemplateData->imaTemplateXattrs.xattrNamesLength) {
		printf("ERROR: IMA_ParseXATTRNAMES: length %lu not equal to string length %u\n",
		       (unsigned long)xattrNamesSize,
		       imaTemplateData->imaTemplateXattrs.xattrNamesLength);
	    }
	}
	if (rc == 0) {
	    /* if xattrNamesLength is > 0, have at least one name */
	    imaTemplateData->imaTemplateXattrs.xattrNamesPtr[0] =
		imaTemplateData->imaTemplateXattrs.xattrNames;
	    imaTemplateData->imaTemplateXattrs.xattrNamesCount++;

	    for (i = 1 ;
		 i < sizeof(((ImaTemplateData *)NULL)->imaTemplateXattrs.xattrNamesPtr) ; i++) {
		/* the | is a separator character */
		imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i] =
		    strchr(imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i-1], '|');
		/* found a | character */
		if (imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i] != NULL) {
		    /* nul terminate the previous string, replace | with nul */
		    *(imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i]) = '\0';
		    imaTemplateData->imaTemplateXattrs.xattrNamesPtr[i] += 1; /* skip the | */
		    imaTemplateData->imaTemplateXattrs.xattrNamesCount++;
		}
		else {
		    break;	/* no more | separators */
		}
	    }
	}
    }
    return rc;
}

/* IMA_ParseXATTRLENGTHS parses an xattrlengths field */

static uint32_t IMA_ParseXATTRLENGTHS(ImaTemplateData	*imaTemplateData,
				      uint8_t 		**buffer,
				      size_t 		*length,
				      int 		littleEndian)
{
    uint32_t 	rc = 0;
    size_t	i;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateXattrs.xattrLengthsLength,
				  buffer, length, littleEndian);
    }
    if (rc == 0) {
	/* range check against total buffer */
	if (*length < imaTemplateData->imaTemplateXattrs.xattrLengthsLength) {
	    printf("ERROR: IMA_ParseXATTRLENGTHS: buffer too small for xattrLengthsLength\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	/* 4-byte lengths, so must be a multiple of 4 */
	else if ((imaTemplateData->imaTemplateXattrs.xattrLengthsLength % 4) != 0) {
	    printf("ERROR: IMA_ParseXATTRLENGTHS: xattrLengthsLength not multiple of 4\n");
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
	/* array of lengths must fit in (guess at) xattrLengths array */
	else if ((imaTemplateData->imaTemplateXattrs.xattrLengthsLength / 4) >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateXattrs.xattrLengths)) {
	    printf("ERROR: IMA_ParseXATTRLENGTHS: xattrLengths length %u too large\n",
		   imaTemplateData->imaTemplateXattrs.xattrLengthsLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if ((imaTemplateData->imaTemplateXattrs.xattrLengthsLength / 4) !=
		 imaTemplateData->imaTemplateXattrs.xattrNamesCount) {
	    printf("ERROR: IMA_ParseXATTRLENGTHS: xattrLengthsLength %lu "
		   "does not match xattrNames Count %lu\n",
		   (unsigned long)imaTemplateData->imaTemplateXattrs.xattrLengthsLength,
		   (unsigned long)imaTemplateData->imaTemplateXattrs.xattrNamesCount);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}

    }
    /* unmarshal the xattrLengths array */ 
    if (rc == 0) {
	for (i = 0 ; i < imaTemplateData->imaTemplateXattrs.xattrLengthsLength / 4 ; i++) {
	    rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateXattrs.xattrLengths[i],
				      buffer, length, littleEndian);
	    imaTemplateData->imaTemplateXattrs.xattrLengthsSum +=
		imaTemplateData->imaTemplateXattrs.xattrLengths[i];
	}
    }
    return rc;
}

/* IMA_ParseXATTRVALUES parses a xattrvalues structure */

static uint32_t IMA_ParseXATTRVALUES(ImaTemplateData	*imaTemplateData,
				     uint8_t 		**buffer,
				     size_t 		*length,
				     int 		littleEndian)
{
    uint32_t 	rc = 0;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateXattrs.xattrValuesLength,
				  buffer, length, littleEndian);
	/* range check against total buffer */
	if (*length < imaTemplateData->imaTemplateXattrs.xattrValuesLength) {
	    printf("ERROR: IMA_ParseXATTRVALUES: buffer too small for xattrValuesLength\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateXattrs.xattrValuesLength !=
		 imaTemplateData->imaTemplateXattrs.xattrLengthsSum) {
	    printf("ERROR: IMA_ParseXATTRVALUES: "
		   "xattrLengths and xattrValuesLength inconsistent\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (imaTemplateData->imaTemplateXattrs.xattrValuesLength >
		 sizeof(((ImaTemplateData *)NULL)->imaTemplateXattrs.xattrValues)) {
	    printf("ERROR: IMA_ParseXATTRVALUES: xattrValues array too small\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* copy the unparsed xattrValues buffer */
    if (rc == 0) {
	memcpy(imaTemplateData->imaTemplateXattrs.xattrValues,
	       *buffer, imaTemplateData->imaTemplateXattrs.xattrValuesLength);
	*buffer += imaTemplateData->imaTemplateXattrs.xattrValuesLength;
	*length -= imaTemplateData->imaTemplateXattrs.xattrValuesLength;
    }
#if 0
    TSS_PrintAll("IMA_ParseXATTRVALUES: xattrvalues",
		 imaTemplateData->imaTemplateXattrs.xattrValues,
		 imaTemplateData->imaTemplateXattrs.xattrValuesLength);
#endif
    return rc;
}

/* IMA_ParseIUID parses a iuid, either a uint16 or uint32 */

static uint32_t IMA_ParseIUID(ImaTemplateData	*imaTemplateData,
			      uint8_t 		**buffer,
			      size_t 		*length,
			      int 		littleEndian)
{
    uint32_t 	rc = 0;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateIUID.iuidLength,
				  buffer, length, littleEndian);
    }
    if ((rc == 0) && (imaTemplateData->imaTemplateIUID.iuidLength > 0)) {
	if (imaTemplateData->imaTemplateIUID.iuidLength == 2) {
	    rc = IMA_Uint16_Unmarshal(&imaTemplateData->imaTemplateIUID.iuid16,
				      buffer, length, littleEndian);
	}
	else if (imaTemplateData->imaTemplateIUID.iuidLength == 4) {
	    rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateIUID.iuid32,
				      buffer, length, littleEndian);
	}
	else {
	    printf("ERROR: IMA_ParseIUID: length %u not 2 or 4 bytes\n",
		   imaTemplateData->imaTemplateIUID.iuidLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
   return rc;
}

/* IMA_ParseIGID parses a igid, either a uint16 or uint32 */

static uint32_t IMA_ParseIGID(ImaTemplateData	*imaTemplateData,
			      uint8_t 		**buffer,
			      size_t 		*length,
			      int 		littleEndian)
{
    uint32_t 	rc = 0;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateIGID.igidLength,
				  buffer, length, littleEndian);
    }
    if ((rc == 0) && (imaTemplateData->imaTemplateIGID.igidLength > 0)) {
	if (imaTemplateData->imaTemplateIGID.igidLength == 2) {
	    rc = IMA_Uint16_Unmarshal(&imaTemplateData->imaTemplateIGID.igid16,
				      buffer, length, littleEndian);
	}
	else if (imaTemplateData->imaTemplateIGID.igidLength == 4) {
	    rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateIGID.igid32,
				      buffer, length, littleEndian);
	}
	else {
	    printf("ERROR: IMA_ParseIGID: length %u not 2 or 4 bytes\n",
		   imaTemplateData->imaTemplateIGID.igidLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    return rc;
}

/* IMA_ParseIMODE parses a */

static uint32_t IMA_ParseIMODE(ImaTemplateData	*imaTemplateData,
			      uint8_t 		**buffer,
			      size_t 		*length,
			      int 		littleEndian)
{
    uint32_t 	rc = 0;

    if (rc == 0) {
	rc = IMA_Uint32_Unmarshal(&imaTemplateData->imaTemplateIMODE.imodeLength,
				  buffer, length, littleEndian);
    }
    if ((rc == 0) && (imaTemplateData->imaTemplateIMODE.imodeLength > 0)) {
	if (imaTemplateData->imaTemplateIMODE.imodeLength == 2) {
	    rc = IMA_Uint16_Unmarshal(&imaTemplateData->imaTemplateIMODE.imode,
				      buffer, length, littleEndian);
	}
	else {
	    printf("ERROR: IMA_ParseIMODE: length %u not 2 bytes\n",
		   imaTemplateData->imaTemplateIMODE.imodeLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    return rc;
}

/* IMA_TemplateData_ReadBuffer() unmarshals the template data fields from the template data byte
   array.

*/

uint32_t IMA_TemplateData_ReadBuffer(ImaTemplateData *imaTemplateData,
				     ImaEvent *imaEvent,
				     int littleEndian)
{
    uint32_t 	rc = 0;
    size_t 	length = imaEvent->template_data_len;
    uint8_t 	*buffer = imaEvent->template_data;
    TemplateDataParseFunction_t templateDataParseFunctions[IMA_PARSE_FUNCTIONS_MAX];
    size_t	i;

    /* initialize all fields, since not all fields are included in all templates */
    if (rc == 0) {
	IMA_TemplateData_Init(imaTemplateData);
    }
    if (rc == 0) {
	rc = IMA_TemplateName_Parse(templateDataParseFunctions,
				    imaTemplateData->templateDataTraceFunctions,
				    IMA_PARSE_FUNCTIONS_MAX,
				    imaEvent);
    }
    for (i = 0 ; (rc == 0) && (templateDataParseFunctions[i] != NULL) ; i++) {
	rc = templateDataParseFunctions[i](imaTemplateData, &buffer, &length, littleEndian);
    }
    /* length should now be zero */
    if (rc == 0) {
	if (length != 0) {
	    printf("ERROR: IMA_TemplateData_ReadBuffer: "
		   "buffer too large (bytes remaining after unmarshaling)\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}

/* IMA_Event_Write() writes an event line to a binary file outFile.

   The write is always big endian, network byte order.
*/

uint32_t IMA_Event_Write(ImaEvent *imaEvent,
			 FILE *outFile)
{
    int rc = 0;
    size_t writeSize;
    uint32_t nbo32;	/* network byte order */

    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->pcrIndex);
	/* write the IMA pcr index */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write pcrIndex, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the IMA digest, name length */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->digest), sizeof(((ImaEvent *)NULL)->digest), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write digest, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the IMA name length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->name_len);
	/* write the IMA name length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write name length, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the name */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->name), imaEvent->name_len, 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write name, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the template data length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->template_data_len);
	/* write the IMA template data length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not template data length , returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    /* write the template data */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->template_data), imaEvent->template_data_len, 1, outFile);
	if (writeSize != 1) {
	    printf("ERROR: IMA_Event_Write: could not write template data, returned %lu\n",
		   (unsigned long)writeSize);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    return rc;
}

/* IMA_Extend() extends the event into the imaPcr.

   An IMA quirk is that, if the event is all zero, all ones is extended into the SHA-1 bank.  Since
   the SHA-256 bank currently gets the SHA-1 value zero extended, it will get 20 ff's and 12 00's.

   halg indicates whether to calculate the digest for the SHA-1 or SHA-256 PCR bank.  The IMA event
   log itself is always SHA-1.

   This function assumes that the same hash algorithm / PCR bank is used for all calls.
*/

uint32_t IMA_Extend(TPMT_HA *imapcr,
		    ImaEvent *imaEvent,
		    TPMI_ALG_HASH hashAlg)
{
    uint32_t 		rc = 0;
    uint16_t		digestSize;
    uint16_t		zeroPad;
    int 		notAllZero;
    unsigned char zeroDigest[SHA256_DIGEST_SIZE];
    unsigned char oneDigest[SHA256_DIGEST_SIZE];

    /* FIXME sanity check TPM_IMA_PCR imaEvent->pcrIndex */

    /* extend based on the previous IMA PCR value */
    if (rc == 0) {
	memset(zeroDigest, 0, SHA256_DIGEST_SIZE);
	memset(oneDigest, 0xff, SHA256_DIGEST_SIZE);
	if (hashAlg == TPM_ALG_SHA1) {
	    digestSize = SHA1_DIGEST_SIZE;
	    zeroPad = 0;
	}
	else if (hashAlg == TPM_ALG_SHA256) {
	    digestSize = SHA256_DIGEST_SIZE;
	    /* pad the SHA-1 event with zeros for the SHA-256 bank */
	    zeroPad = SHA256_DIGEST_SIZE - SHA1_DIGEST_SIZE;
	}
	else {
	    printf("ERROR: IMA_Extend: Unsupported hash algorithm: %04x\n", hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    if (rc == 0) {
	notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
	imapcr->hashAlg = hashAlg;
#if 1
	TSS_PrintAll("IMA_Extend: Start PCR", (uint8_t *)&imapcr->digest, digestSize);
	TSS_PrintAll("IMA_Extend: SHA-256 Pad", zeroDigest, zeroPad);
#endif
	if (notAllZero) {
	    TSS_PrintAll("IMA_Extend: Extend", (uint8_t *)&imaEvent->digest, SHA1_DIGEST_SIZE);
	    rc = TSS_Hash_Generate(imapcr,
				   digestSize, (uint8_t *)&imapcr->digest,
				   SHA1_DIGEST_SIZE, &imaEvent->digest,
				   /* SHA-1 PCR extend gets zero padded */
				   zeroPad, zeroDigest,
				   0, NULL);
#if 1
	    TSS_PrintAll("IMA_Extend: notAllZero End PCR",
			 (uint8_t *)&imapcr->digest, digestSize);
#endif
	}
	/* IMA has a quirk where, when it places all all zero digest into the measurement log, it
	   extends all ones into IMA PCR */
	else {
	    TSS_PrintAll("IMA_Extend: Extend", (uint8_t *)oneDigest, SHA1_DIGEST_SIZE);
	    rc = TSS_Hash_Generate(imapcr,
				   digestSize, (uint8_t *)&imapcr->digest,
				   SHA1_DIGEST_SIZE, oneDigest,
				   /* SHA-1 gets zero padded */
				   zeroPad, zeroDigest,
				   0, NULL);
#if 1
	    TSS_PrintAll("IMA_Extend: allZero End PCR",
			 (uint8_t *)&imapcr->digest, digestSize);
#endif
	}
    }
    if (rc != 0) {
	printf("ERROR: IMA_Extend: could not extend imapcr, rc %08x\n", rc);
    }
    return rc;
}

/* IMA_VerifyImaDigest() verifies the IMA digest against the hash of the template data.

   This handles the SHA-1 IMA event log.
*/

uint32_t IMA_VerifyImaDigest(uint32_t *badEvent, /* TRUE if hash does not match */
			     ImaEvent *imaEvent, /* the current IMA event being processed */
			     int eventNum)	 /* the current IMA event number being processed */
{
    uint32_t 	rc = 0;
    int		irc;
    TPMT_HA 	calculatedImaDigest;
    
    /* calculate the hash of the template data */
    if (rc == 0) {
	calculatedImaDigest.hashAlg = TPM_ALG_SHA1;
	/* standard case, hash of entire template data */
	if (imaEvent->nameInt != IMA_FORMAT_IMA) {
	    rc = TSS_Hash_Generate(&calculatedImaDigest,
				   imaEvent->template_data_len, imaEvent->template_data,
				   0, NULL);
	}
	/* special case of "ima" template, hash of File Data Hash || File Name padded with zeros to
	   256 bytes */
	else {
	    ImaTemplateData imaTemplateData;
	    int zeroPadLength;
	    uint8_t zeroPad[256];
	    if (rc == 0) {
		rc = IMA_TemplateData_ReadBuffer(&imaTemplateData,
						 imaEvent,
						 TRUE);	/* FIXME littleEndian */
	    }
	    if (rc == 0) {
		if (imaTemplateData.imaTemplateNNG.fileNameLength > sizeof(zeroPad)) {
		    printf("ERROR: IMA_VerifyImaDigest: ima template file name length %u > %lu\n",
			   imaTemplateData.imaTemplateNNG.fileNameLength,
			   (unsigned long)sizeof(zeroPad));
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
	    }
	    if (rc == 0) {
		memset(zeroPad, 0, sizeof(zeroPad));
		/* subtract safe after above length check */
		zeroPadLength = sizeof(zeroPad) - imaTemplateData.imaTemplateNNG.fileNameLength;
	    }
	    if (rc == 0) {
		rc = TSS_Hash_Generate(&calculatedImaDigest,
				       SHA1_DIGEST_SIZE, &imaTemplateData.imaTemplateDNG.fileDataHash,
				       imaTemplateData.imaTemplateNNG.fileNameLength,
				       &imaTemplateData.imaTemplateNNG.fileName,
				       zeroPadLength, zeroPad,
				       0, NULL);
	    }
	}
    }
    /* compare the calculated hash to the event digest received from the client */
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_PrintAll("IMA_VerifyImaDigest: Received IMA digest",
				   imaEvent->digest, SHA1_DIGEST_SIZE);
	if (tssUtilsVerbose) TSS_PrintAll("IMA_VerifyImaDigest: Calculated IMA digest",
				   (uint8_t *)&calculatedImaDigest.digest, SHA1_DIGEST_SIZE);

	irc = memcmp(imaEvent->digest, &calculatedImaDigest.digest, SHA1_DIGEST_SIZE);
	if (irc == 0) {
	    if (tssUtilsVerbose) printf("IMA_VerifyImaDigest: IMA digest verified, event %u\n",
					eventNum);
	    *badEvent = FALSE;
	}
	else {
	    printf("ERROR: IMA_VerifyImaDigest: IMA digest did not verify, event %u\n",
		   eventNum);
	    *badEvent = TRUE;
	}
    }
    return rc;
}

/* IMA_Uint16_Unmarshal() converts a uint8_t (from an input stream) to host byte order
 */

static uint32_t IMA_Uint16_Unmarshal(uint16_t 	*out,
				     uint8_t 	**buffer,
				     size_t 	*length,
				     int 	littleEndian)
{
    uint32_t 	rc = 0;

    *out = 0;
    /* bounds check the length */
    if (rc == 0) {
	if (*length < sizeof(uint16_t)) {
	    printf("ERROR: IMA_Uint16_Convert: buffer too small for length\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	/* little endian input */
	if (littleEndian) {
	    *out = (((uint16_t)(*buffer)[0]) <<  0) |
		   (((uint16_t)(*buffer)[1]) <<  8);
	}
	/* big endian input */
	else {
	    *out = (((uint16_t)(*buffer)[0]) <<  8) |
		   (((uint16_t)(*buffer)[1]) <<  0);
	}
	*buffer += sizeof(uint16_t);
	*length -= sizeof(uint16_t);
    }
    return rc;
}

/* IMA_Uint32_Ummarshal() converts a uint8_t (from an input stream) to host byte order
 */

static uint32_t IMA_Uint32_Unmarshal(uint32_t 	*out,
				     uint8_t	**buffer,
				     size_t 	*length,
				     int 	littleEndian)
{
    uint32_t 	rc = 0;

    *out = 0;
    /* bounds check the length */
    if (rc == 0) {
	if (*length < sizeof(uint32_t)) {
	    printf("ERROR: IMA_Uint32_Unmarshal: buffer too small for length\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	/* little endian input */
	if (littleEndian) {
	    *out = (((uint32_t)(*buffer)[0]) <<  0) |
		   (((uint32_t)(*buffer)[1]) <<  8) |
		   (((uint32_t)(*buffer)[2]) << 16) |
		   (((uint32_t)(*buffer)[3]) << 24);
	}
	/* big endian input */
	else {
	    *out = (((uint32_t)(*buffer)[0]) << 24) |
		   (((uint32_t)(*buffer)[1]) << 16) |
		   (((uint32_t)(*buffer)[2]) <<  8) |
		   (((uint32_t)(*buffer)[3]) <<  0);
	}
	*buffer += sizeof(uint32_t);
	*length -= sizeof(uint32_t);
    }
    return rc;
}

/* IMA_Uint32_Convert() converts a uint8_t (from an input stream) to host byte order
 */

static uint32_t IMA_Uint32_Convert(const uint8_t *stream,
				   int littleEndian)
{
    uint32_t out = 0;

    /* little endian input */
    if (littleEndian) {
	out = (stream[0] <<  0) |
	      (stream[1] <<  8) |
	      (stream[2] << 16) |
	      (stream[3] << 24);
    }
    /* big endian input */
    else {
	out = (stream[0] << 24) |
	      (stream[1] << 16) |
	      (stream[2] <<  8) |
	      (stream[3] <<  0);
    }
    return out;
}

/* IMA_Strn2cpy() copies src to dest, including a NUL terminator

   It checks that src is nul terminated within srcLength bytes.
   It checks that src fits into dest within destLength bytes

   Returns error if either the src is not nul terminated or will not fit in dest.
*/

static uint32_t IMA_Strn2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength)
{
    uint32_t rc = 0;
    int done = 0;

    while ((destLength > 0) && (srcLength > 0)) {
	*dest = *src;
	if (*dest == '\0') {
	    done = 1;
	    break;
	}
	else {
	    dest++;
	    src++;
	    destLength--;
	    srcLength--;
	}
    }
    if (!done) {
	rc = TSS_RC_INSUFFICIENT_BUFFER;
    }
    return rc;
}

/* IMA_Strc2cpy() copies src to dest, including a NUL terminator

   It checks that src is colon terminated within srcLength bytes.
   It checks that src fits into dest within destLength bytes

   Returns error if either the src is not nul terminated or will not fit in dest.
*/

static uint32_t IMA_Strc2cpy(char *dest, const uint8_t *src,
			     size_t destLength, size_t srcLength)
{
    uint32_t rc = 0;
    int done = 0;

    while ((destLength > 0) && (srcLength > 0)) {
	*dest = *src;
	if (*dest == ':') {
	    *(dest+1) = '\0';	/* append nul */
	    done = 1;
	    break;
	}
	else {
	    dest++;
	    src++;
	    destLength--;
	    srcLength--;
	}
    }
    if (!done) {
	rc = TSS_RC_INSUFFICIENT_BUFFER;
    }
    return rc;
}

/* IMA_Event_Marshal() marshals an ImaEvent structure */

TPM_RC IMA_Event_Marshal(ImaEvent *source,
			 uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->name_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->name, source->name_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->template_data_len, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->template_data, source->template_data_len,
			       written, buffer, size);
    }
    return rc;
}

/* IMA_Event_PcrExtend() extends PCR digests with the digest from the ImaEvent event log
   entry.

   Bank 0 is SHA-1.  Bank 1 is SHA-256.

   The function supports all PCRs, even though the PCRs are limited in practice.

*/

uint32_t IMA_Event_PcrExtend(TPMT_HA pcrs[IMA_PCR_BANKS][IMPLEMENTATION_PCR],
			     ImaEvent *imaEvent)
{
    TPM_RC 		rc = 0;
    uint8_t		eventData[SHA256_DIGEST_SIZE];
    
    /* validate PCR number */
    if (rc == 0) {
	if (imaEvent->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: IMA_Event_PcrExtend: PCR number %u %08x out of range\n",
		   imaEvent->pcrIndex, imaEvent->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    /* process each event hash algorithm */
    if (rc == 0) {
	unsigned char 	zeroDigest[SHA1_DIGEST_SIZE];
	int 		notAllZero;
	memset(zeroDigest, 0, SHA1_DIGEST_SIZE);
	notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
	/* for the SHA-256 zero extend */
	memset(eventData, 0, SHA256_DIGEST_SIZE);
	
	/* IMA has a quirk where some measurements store a zero digest in the event log, but
	   extend ones into PCR 10 */
	if (notAllZero) {
	    memcpy(eventData, imaEvent->digest, SHA1_DIGEST_SIZE);
	}
	else {
	    memset(eventData, 0xff, SHA1_DIGEST_SIZE);
	}
    }
    /* SHA-1 */
    if (rc == 0) {
	rc = TSS_Hash_Generate(&pcrs[0][imaEvent->pcrIndex],
			       SHA1_DIGEST_SIZE,
			       (uint8_t *)&pcrs[0][imaEvent->pcrIndex].digest,
			       SHA1_DIGEST_SIZE,
			       eventData,
			       0, NULL);
    }
    /* SHA-256 */
    if (rc == 0) {
	rc = TSS_Hash_Generate(&pcrs[1][imaEvent->pcrIndex],
			       SHA256_DIGEST_SIZE,
			       (uint8_t *)&pcrs[1][imaEvent->pcrIndex].digest,
			       SHA256_DIGEST_SIZE,
			       eventData,
			       0, NULL);
    }
    return rc;
}

#if 0
/* IMA_Event_ToString() converts the ImaEvent structure to a hexascii string, big endian. */

uint32_t IMA_Event_ToString(char **eventString,	/* freed by caller */
			    ImaEvent *imaEvent)
{
    int 	rc = 0;
    size_t	length;
    
    /* calculate size of string, from ImaEvent structure */
    if (rc == 0) {
	length = ((sizeof(uint32_t) + SHA1_DIGEST_SIZE + sizeof(uint32_t) +
		   TCG_EVENT_NAME_LEN_MAX + 1 + sizeof(uint32_t) +
		   imaEvent->template_data_len) * 2) + 1;
    }
    if (rc == 0) {
	*eventString = malloc(length);
	if (*eventString == NULL) {
	    printf("ERROR: IMA_Event_ToString: error allocating %lu bytes\n", length);
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	memset(*eventString, '\0', length);
	char *p = *eventString;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->pcrIndex);
	p += sizeof(uint32_t)* 2;

	Array_Print(p, NULL, imaEvent->digest, SHA1_DIGEST_SIZE);
	p += SHA1_DIGEST_SIZE * 2;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->name_len);
	p += sizeof(uint32_t) * 2;

	Array_Print(p, NULL, FALSE, (uint8_t *)imaEvent->name, imaEvent->name_len);
	p += imaEvent->name_len * 2;

	sprintf(p, "%08lx", (long unsigned int)imaEvent->template_data_len);
	p += sizeof(uint32_t) * 2;

	Array_Print(p, NULL, FALSE, imaEvent->template_data, imaEvent->template_data_len);
	p += imaEvent->template_data_len * 2;
	/* printf("IMA_Event_ToString: result\n:%s:\n", *eventString); */
    }
    return rc;
}

#endif

