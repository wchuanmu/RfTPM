/********************************************************************************/
/*										*/
/*			    CertifyX509						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2019 - 2021.					*/
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

/* CertifyX509 exercises the TPM2_CertifyX509 command.  It:

   - Creates a partialCertificate parameter
   - Runs the TPM2_CertifyX509 command
   - Reconstructs the X509 certificate from the addedToCertificate and signature outputs
*/

/* mbedtls does not support this utility */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cryptoutils.h"

#ifndef TPM_TSS_MBEDTLS

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssfile.h>

/* NOTE: This is currently openssl only. */
#include <ekutils.h>

/* definition of the partial certificate, from Part 3 TPM2_CertifyX509.
   1)	Signature Algorithm Identifier (optional)
   2)	Issuer (mandatory)
   3)	Validity (mandatory)
   4)	Subject Name (mandatory)
   5)	Extensions (mandatory)
*/

typedef struct {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
} TPM_PARTIAL_CERT_VALIDITY;

/* partial certificate TPM input parameter entire structure */
typedef struct {
    X509_ALGOR *algorithm;	/* signature algorithm */
    X509_NAME *issuer;
    TPM_PARTIAL_CERT_VALIDITY *validity;
    X509_NAME *subject;
    STACK_OF(X509_EXTENSION) *extensions;
} TPM_PARTIAL_CERT;

ASN1_SEQUENCE(TPM_PARTIAL_CERT_VALIDITY) = {
    ASN1_SIMPLE(TPM_PARTIAL_CERT_VALIDITY, notBefore, ASN1_TIME),
    ASN1_SIMPLE(TPM_PARTIAL_CERT_VALIDITY, notAfter, ASN1_TIME),
#if OPENSSL_VERSION_NUMBER < 0x10100000
} ASN1_SEQUENCE_END(TPM_PARTIAL_CERT_VALIDITY)
#else
} static_ASN1_SEQUENCE_END(TPM_PARTIAL_CERT_VALIDITY)
#endif

/* the signature algorithm is optional while the extension list is mandatory */
ASN1_SEQUENCE(TPM_PARTIAL_CERT) = {
    ASN1_OPT(TPM_PARTIAL_CERT, algorithm, X509_ALGOR),
    ASN1_SIMPLE(TPM_PARTIAL_CERT, issuer, X509_NAME),
    ASN1_SIMPLE(TPM_PARTIAL_CERT, validity, TPM_PARTIAL_CERT_VALIDITY),
    ASN1_SIMPLE(TPM_PARTIAL_CERT, subject, X509_NAME),
    ASN1_EXP_SEQUENCE_OF(TPM_PARTIAL_CERT, extensions, X509_EXTENSION, 3),
#if OPENSSL_VERSION_NUMBER < 0x10100000
} ASN1_SEQUENCE_END(TPM_PARTIAL_CERT)
#else
} static_ASN1_SEQUENCE_END(TPM_PARTIAL_CERT)
#endif

DECLARE_ASN1_FUNCTIONS(TPM_PARTIAL_CERT)
IMPLEMENT_ASN1_FUNCTIONS(TPM_PARTIAL_CERT)

/* add to signature TPM output parameter */

typedef struct  {
    ASN1_INTEGER *version;
    ASN1_INTEGER *serialNumber;
    X509_ALGOR   *signatureAlgorithm;
    X509_PUBKEY  *key;
} TPM_ADDTOCERT;

ASN1_SEQUENCE(TPM_ADDTOCERT) = {
    ASN1_EXP_OPT(TPM_ADDTOCERT, version, ASN1_INTEGER, 0),
    ASN1_SIMPLE(TPM_ADDTOCERT, serialNumber, ASN1_INTEGER),
    ASN1_SIMPLE(TPM_ADDTOCERT, signatureAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(TPM_ADDTOCERT, key, X509_PUBKEY),
#if OPENSSL_VERSION_NUMBER < 0x10100000
} ASN1_SEQUENCE_END(TPM_ADDTOCERT)
#else
} static_ASN1_SEQUENCE_END(TPM_ADDTOCERT)
#endif

DECLARE_ASN1_FUNCTIONS(TPM_ADDTOCERT)
IMPLEMENT_ASN1_FUNCTIONS(TPM_ADDTOCERT)

static void printUsage(void);

TPM_RC addPartialCertExtension(TPM_PARTIAL_CERT *partialCertificate,
			       X509 		*x509Certificate,
			       int nid, const char *value);
TPM_RC addPartialCertExtensionTpmaOid(TPM_PARTIAL_CERT  *partialCertificate,
				      X509 		*x509Certificate,
				      uint32_t 		tpmaObject);
TPM_RC createPartialCertificate(TPM_PARTIAL_CERT *certificate,
				X509 *x509Certificate,
				uint8_t *partialCertificateDer,
				uint16_t *partialCertificateDerLength,
				size_t partialCertificateDerSize,
				const char *keyUsage,
				uint32_t tpmaObject,
				int addTpmaObject,
				int subeqiss);
TPM_RC reformCertificate(X509 			*x509Certificate,
			 TPMI_ALG_HASH		halg,
			 TPMI_ALG_SIG_SCHEME   	scheme,
			 const TPM_ADDTOCERT	*addToCert,
			 TPMT_SIGNATURE 	*tSignature);
TPM_RC addSignatureRsa(X509 		*x509Certificate,
		       TPMI_ALG_HASH	halg,
		       TPMT_SIGNATURE 	*tSignature);
#ifndef TPM_TSS_NOECC
TPM_RC addSignatureEcc(X509 		*x509Certificate,
		       TPMI_ALG_HASH	halg,
		       TPMT_SIGNATURE 	*signature);
#endif	/* TPM_TSS_NOECC */

int verbose = FALSE;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    CertifyX509_In 		in;
    CertifyX509_Out 		out;
    TPMI_DH_OBJECT		objectHandle = 0;
    TPMI_DH_OBJECT		signHandle = 0;
    unsigned int		algCount = 0;
    TPMI_ALG_SIG_SCHEME    	scheme = TPM_ALG_ERROR;
    TPMI_RSA_KEY_BITS 		keyBits = 0;
    TPMI_ECC_CURVE		curveID = 0;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    unsigned int 		bit = 0;
    int 			testBit = FALSE;
    const char			*keyPassword = NULL;
    const char			*objectPassword = NULL;
    const char			*outPartialCertificateFilename = NULL;
    const char			*outCertificateFilename = NULL;
    const char			*addedToCertificateFilename = NULL;
    const char			*tbsDigestFilename = NULL;
    const char			*signatureFilename = NULL;

    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RS_PW;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    int				subeqiss = FALSE;	/* TRUE: subject = issuer */
    const char 			*keyUsage = "critical,digitalSignature,keyCertSign,cRLSign";
    uint32_t			tpmaObject = 0;
    int				addTpmaObject = FALSE;
    X509 			*x509Certificate = NULL;
    unsigned char 		*x509Der = NULL;
    uint32_t 			x509DerLength = 0;
    TPM_PARTIAL_CERT 		*partialCertificate = NULL;
    TPM_ADDTOCERT 		*addToCert = NULL;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    curveID = curveID;		/* no longer used, get from parent */
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&objectHandle);
	    }
	    else {
		printf("Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		objectPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&signHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
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
	else if (strcmp(argv[i], "-rsa") == 0) {
	    scheme = TPM_ALG_RSASSA;
	    algCount++;
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%hu", &keyBits);
	    }
	    else {
		printf("Missing keysize parameter for -rsa\n");
		printUsage();
	    }
	}
#ifndef TPM_TSS_NOECC
	else if (strcmp(argv[i], "-ecc") == 0) {
	    scheme = TPM_ALG_ECDSA;
	    algCount++;
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"nistp256") == 0) {
		    curveID = TPM_ECC_NIST_P256;
		}
		else if (strcmp(argv[i],"nistp384") == 0) {
		    curveID = TPM_ECC_NIST_P384;
		}
		else {
		    printf("Bad curve parameter %s for -ecc\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-ecc option needs a value\n");
		printUsage();
	    }
	}
#endif	/* TPM_TSS_NOECC */
	else if (strcmp(argv[i],"-ku") == 0) {
	    i++;
	    if (i < argc) {
		keyUsage = argv[i];
	    }
	    else {
		printf("-ku option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iob") == 0) {
	    i++;
	    if (i < argc) {
		addTpmaObject = TRUE;
		sscanf(argv[i], "%x", &tpmaObject);
	    }
	    else {
		printf("-iob option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sub") == 0) {
	    subeqiss = TRUE;
	}
	else if (strcmp(argv[i],"-opc") == 0) {
	    i++;
	    if (i < argc) {
		outPartialCertificateFilename = argv[i];
	    }
	    else {
		printf("-opc option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ocert") == 0) {
	    i++;
	    if (i < argc) {
		outCertificateFilename = argv[i];
	    }
	    else {
		printf("-ocert option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oa") == 0) {
	    i++;
	    if (i < argc) {
		addedToCertificateFilename = argv[i];
	    }
	    else {
		printf("-oa option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-otbs") == 0) {
	    i++;
	    if (i < argc) {
		tbsDigestFilename = argv[i];
	    }
	    else {
		printf("-otbs option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-os") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-os option needs a value\n");
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
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (objectHandle == 0) {
	printf("Missing object handle parameter -ho\n");
	printUsage();
    }
    if (signHandle == 0) {
	printf("Missing sign handle parameter -hk\n");
	printUsage();
    }
    if (algCount == 0) {
	printf("One of -rsa, -ecc must be specified\n");
	printUsage();
    }
    if (algCount > 1) {
	printf("Only one of -rsa, -ecc can be specified\n");
	printUsage();
    }
    if (rc == 0) {
	/* Handle of the object to be certified */
	in.objectHandle = objectHandle;
	/* Handle of key that will perform certifying */
	in.signHandle = signHandle;
	in.inScheme.scheme = scheme;
	if (scheme == TPM_ALG_RSASSA) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else {	/* ecc */
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
	in.reserved.t.size = 0;
    }
    /* initialize a new, empty X509 structure.  It will be used to reform the certificate from
       the response parameters. */
    if (rc == 0) {
	x509Certificate = X509_new();				/* freed @1 */
	if (x509Certificate == NULL) {
	    printf("main: Error in X509_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* initialize a new, empty TPM_PARTIAL_CERT structure.  It will be used to form the
       partialCertificate command parameter */
    if (rc == 0) {
	partialCertificate = TPM_PARTIAL_CERT_new();		/* freed @2 */
	if (partialCertificate == NULL) {
	    printf("main: Error in TPM_PARTIAL_CERT_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* form partial certificate and populate the X509 certificate with the values */
    if (rc == 0) {
	rc = createPartialCertificate(partialCertificate,
				      x509Certificate,
				      in.partialCertificate.t.buffer,
				      &in.partialCertificate.b.size,
				      sizeof(in.partialCertificate.t.buffer),
				      keyUsage,
				      tpmaObject,
				      addTpmaObject,
				      subeqiss);
    }
    /* for debug testing */
    if ((rc == 0) && (testBit)) {
	unsigned int bitInByte = bit % 8;
	unsigned int byteInDer = bit / 8;
	if (byteInDer <= in.partialCertificate.b.size) {
	    if (verbose) {
		printf("main: Testing byte %u bit %u\n", byteInDer, bitInByte);
		printf("main: Byte was %02x\n", in.partialCertificate.t.buffer[byteInDer]);
	    }
	    in.partialCertificate.t.buffer[byteInDer] ^= (1 << bitInByte);
	    if (verbose) printf("main: Byte is %02x\n", in.partialCertificate.t.buffer[byteInDer]);
	}
	else {
	    printf("Bad -bit parameter, byte %u, DER length %u\n",
		   byteInDer, in.partialCertificate.b.size);
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    /* for debug, or stop here for sample of how to create the partialCertificate parameter */
    if (rc == 0) {
	if (outPartialCertificateFilename != NULL) {
	    rc = TSS_File_WriteBinaryFile(in.partialCertificate.b.buffer,
					  in.partialCertificate.b.size,
					  outPartialCertificateFilename);
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CertifyX509,
			 sessionHandle0, objectPassword, sessionAttributes0,
			 sessionHandle1, keyPassword, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("certifyx509: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    /*
      write response parameters for debug
    */
    /* added to certificate */
    if ((rc == 0) && (addedToCertificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.addedToCertificate.t.buffer,
				      out.addedToCertificate.t.size,
				      addedToCertificateFilename);
    }
    /*  to be signed digest */
    if ((rc == 0) && (tbsDigestFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.tbsDigest.t.buffer,
				      out.tbsDigest.t.size,
				      tbsDigestFilename);
    }
    /* signature */
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu,
				     signatureFilename);
    }
    if (rc == 0) {
	if (verbose) TSS_TPMT_SIGNATURE_Print(&out.signature, 0);
    }
    /* convert the TPM output addedToCertificate DER to the OpenSSL structure */
    if (rc == 0) {
	const unsigned char *tmpptr = out.addedToCertificate.t.buffer;
	addToCert = d2i_TPM_ADDTOCERT(NULL,		/* freed @3 */
				      &tmpptr, out.addedToCertificate.t.size);
	if (addToCert == NULL) {
	    printf("d2i_TPM_ADDTOCERT failed %p\n", addToCert);
	    rc = EXIT_FAILURE;
	}
    }
    /* reform the signed certificate from the original X509 input plus the response parameters */
    if (rc == 0) {
	rc = reformCertificate(x509Certificate,
			       halg, scheme,
			       addToCert,
			       &out.signature);
    }
    if (rc == 0) {
	if (verbose) X509_print_fp(stdout, x509Certificate);	/* for debug */
	rc = convertX509ToDer(&x509DerLength,
			      &x509Der,				/* freed @4 */
			      x509Certificate);
    }
    if ((rc == 0) && (outCertificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(x509Der, x509DerLength,
				      outCertificateFilename);
    }
    if (x509Certificate != NULL) {
	X509_free(x509Certificate);			/* @1 */
    }
    if (partialCertificate != NULL) {
	TPM_PARTIAL_CERT_free(partialCertificate);	/* @2 */
    }
    if (addToCert != NULL) {
	TPM_ADDTOCERT_free(addToCert);			/* @3 */
    }
    free(x509Der);					/* @4 */
    return rc;
}

/* example of a 20 year validity */
#define CERT_DURATION (60 * 60 * 24 * ((365 * 20) + 5))		/* +5 for leap years */

/* in this test, the issuer and subject are the same, making a self signed certificate.  This is
   simply so that openssl can be used to verify the certificate signature.
 */

char *issuerEntries[] = {
    "US"			,
    "NY"			,
    "Yorktown"			,
    "IBM"			,
    NULL			,
    "CA"			,
    NULL
};

char *subjectEntries[] = {
    "US"			,
    "NY"			,
    "Yorktown"			,
    "IBM"			,
    NULL			,
    "Subject"			,
    NULL
};

/* createPartialCertificate() forms the partialCertificate DER.  It starts with an empty X509 and
   TPM_PARTIAL_CERT structures.  It adds the needed parameters to both structures.  It then
   serializes the TPM_PARTIAL_CERT structure to partialCertificateDer;

   subeqiss FALSE: subject name is independent of issuer name
   subeqiss TRUE:  subject name is the same as the issuer name
*/

TPM_RC createPartialCertificate(TPM_PARTIAL_CERT *partialCertificate,	/* input / output */
				X509 *x509Certificate,			/* input / output */
				uint8_t *partialCertificateDer,		/* output */
				uint16_t *partialCertificateDerLength,
				size_t partialCertificateDerSize,	/* input, size of
									   partialCertificateDer */
				const char *keyUsage,
				uint32_t tpmaObject,
				int addTpmaObject,
				int subeqiss)				/* subject variation */
{
    TPM_RC 	rc = 0;
    int		irc;
    ASN1_TIME	*arc;			/* return code */

    size_t	issuerEntriesSize = sizeof(issuerEntries)/sizeof(char *);
    size_t	subjectEntriesSize = sizeof(subjectEntries)/sizeof(char *);
    uint8_t 	*tmpPartialDer = NULL;	/* for the i2d */

    /* add issuer */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Adding issuer, size %lu\n",
			    (unsigned long)issuerEntriesSize);
	/* _new allocates the member.  free it because createX509Name() allocates a new structure */
	X509_NAME_free(partialCertificate->issuer);
	partialCertificate->issuer = NULL;
	rc = createX509Name(&partialCertificate->issuer,	/* freed @1 */
			    issuerEntriesSize,
			    issuerEntries);
    }
    if (rc == 0) {
	irc = X509_set_issuer_name(x509Certificate, partialCertificate->issuer);
	if (irc != 1) {
	    printf("createPartialCertificate: Error setting issuer\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /*
      validity before
    */
    if (rc == 0) {
	/* set to today */
	arc = X509_gmtime_adj(partialCertificate->validity->notBefore ,0L);
	if (arc == NULL) {
	    printf("createPartialCertificate: Error setting notBefore time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	irc = X509_set1_notBefore(x509Certificate, partialCertificate->validity->notBefore);
	if (irc == 0) {
	    printf("createPartialCertificate: Error setting notBefore time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /*
      validity after
    */
    if (rc == 0) {
	/* set to duration */
	arc = X509_gmtime_adj(partialCertificate->validity->notAfter, CERT_DURATION);
	if (arc == NULL) {
	    printf("createPartialCertificate: Error setting notAfter time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	irc = X509_set1_notAfter(x509Certificate,partialCertificate->validity->notAfter);
	if (irc == 0) {
	    printf("createPartialCertificate: Error setting notAfter time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add subject */
    if (rc == 0) {
	/* normal case */
	if (!subeqiss) {
	    if (verbose) printf("createPartialCertificate: Adding subject, size %lu\n",
				(unsigned long)subjectEntriesSize);
	    X509_NAME_free(partialCertificate->subject);
	    partialCertificate->subject = NULL;
	    rc = createX509Name(&partialCertificate->subject,	/* freed @2 */
				subjectEntriesSize,
				subjectEntries);
	}
	/* special case, self signed CA, make the subject the same as the issuer */
	else {
	    if (verbose) printf("createPartialCertificate: Adding subject (issuer), size %lu\n",
				(unsigned long)issuerEntriesSize);
	    X509_NAME_free(partialCertificate->subject);
	    partialCertificate->subject = NULL;
	    rc = createX509Name(&partialCertificate->subject,	/* freed @2 */
				issuerEntriesSize,
				issuerEntries);
	}
    }
    if (rc == 0) {
	irc = X509_set_subject_name(x509Certificate, partialCertificate->subject);
	if (irc != 1) {
	    printf("createPartialCertificate: Error setting subject\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add some certificate extensions, requires corresponding bits in subject key */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Adding extensions\n");
	rc = addPartialCertExtension(partialCertificate,
				     x509Certificate,
				     NID_key_usage, keyUsage);
    }
    /* optional TPMA_OBJECT extension */
    /* From TCG OID registry tcg-tpmaObject 2.23.133.10.1.1.1  */
    if (rc == 0) {
	if (addTpmaObject) {
	    rc = addPartialCertExtensionTpmaOid(partialCertificate,
						x509Certificate,
						tpmaObject);
	}
    }
    /* serialize the openSSL partial certificate structure to a DER stream */
    if (rc == 0) {
	*partialCertificateDerLength =
	    (uint16_t)i2d_TPM_PARTIAL_CERT(partialCertificate,
					   &tmpPartialDer);	/* freed @3 */
    }
    /* check the i2d size, and copy the DER to the TPM input parameter */
    if (rc == 0) {
	if (*partialCertificateDerLength <= partialCertificateDerSize) {
	    memcpy(partialCertificateDer, tmpPartialDer, *partialCertificateDerLength);
	}
	else {
	    printf("createPartialCertificate: Partial cert size %u too large\n",
		   *partialCertificateDerLength);
	    rc = TSS_RC_X509_ERROR;
	}
    }
#if 0
    /* for debug.  The X509 structure is incomplete and so will trace with errors */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Trace preliminary certificate\n");
	if (verbose) X509_print_fp(stdout, x509Certificate);
    }
#endif
    OPENSSL_free(tmpPartialDer);	/* @3 */
    return rc;
}

/* addPartialCertExtension() adds the extension type 'nid' to the partial certificate

 */

TPM_RC addPartialCertExtension(TPM_PARTIAL_CERT *partialCertificate,
			       X509 		*x509Certificate,
			       int nid, const char *value)
{
    TPM_RC 		rc = 0;
    X509_EXTENSION 	*extension = NULL;	/* freed @1 */

    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	/* the cast is required for the older openssl 1.0 API */
	extension = X509V3_EXT_conf_nid(NULL, NULL,	/* freed @1 */
					nid, (char *)value);
#else
	extension = X509V3_EXT_conf_nid(NULL, NULL,	/* freed @1 */
					nid, value);
#endif
	if (extension == NULL) {
	    printf("addPartialCertExtension: Error creating nid %i extension %s\n",
		   nid, value);
	    rc = -1;
	}
    }
    if (rc == 0) {
	STACK_OF(X509_EXTENSION) *src =
	    X509v3_add_ext(&partialCertificate->extensions,
			   extension,	/* the extension to add */
			   -1);		/* location - append */
	if (src == NULL) {
	    printf("addPartialCertExtension: Error adding nid %i extension %s\n",
		   nid, value);
	}
    }
    if (rc == 0) {
	int irc = X509_add_ext(x509Certificate,
			       extension,	/* the extension to add */
			       -1);		/* location - append */
	if (irc != 1) {
	    printf("addCertExtension: Error adding oid to extension\n");
	}
    }
    if (extension != NULL) {
	X509_EXTENSION_free(extension);		/* @1 */
    }
    return rc;
}

/* addPartialCertExtensionTpmaOid() adds the tpmaObject extension oid to the X509 certificate

 */

TPM_RC addPartialCertExtensionTpmaOid(TPM_PARTIAL_CERT  *partialCertificate,
				      X509 		*x509Certificate,
				      uint32_t 		tpmaObject)
{
    TPM_RC 		rc = 0;
    X509_EXTENSION 	*extension = NULL;	/* freed @1 */


    uint8_t tpmaObjectOid[] = {0x06, 0x07, 0x67, 0x81, 0x05, 0x0A, 0x01, 0x01, 0x01};
    const uint8_t *tmpOidPtr;	/* const for d2i_ASN1_OBJECT */

    /* BIT STRING 0x03 length 5 no padding 0, 4 dummy bytes of TPMA_OBJECT */
    uint8_t tpmaObjectData[] = {0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};
    ASN1_OBJECT *object = NULL;
    ASN1_OCTET_STRING *osData = NULL;
    uint8_t *tmpOdPtr;
    uint32_t tpmaObjectNbo = htonl(tpmaObject);


    /* create the object */
    if (rc == 0) {
	tmpOidPtr = tpmaObjectOid;
	object = d2i_ASN1_OBJECT(NULL, &tmpOidPtr, sizeof(tpmaObjectOid));	/* freed @2 */
	if (object ==  NULL) {
	    printf("addPartialCertExtensionTpmaOid: d2i_ASN1_OBJECT failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	osData = ASN1_OCTET_STRING_new();	/* freed @3 */
	if (osData == NULL) {
	    printf("addPartialCertExtensionTpmaOid: ASN1_OCTET_STRING_new failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* copy the TPMA_OBJECT bytes to the BIT STRING place holder, set the result in the
       ASN1_OCTET_STRING */
    if (rc == 0) {
	tmpOdPtr = tpmaObjectData;
	memcpy(tmpOdPtr + 3, &tpmaObjectNbo, sizeof(uint32_t));
	ASN1_OCTET_STRING_set(osData, tmpOdPtr, sizeof (tpmaObjectData));
    }
    /* create the extension with the TPMA_OBJECT in the ASN1_OBJECT */
    if (rc == 0) {
	extension = X509_EXTENSION_create_by_OBJ(NULL,		/* freed @1 */
						 object,
						 0,		/* int crit */
						 osData);
	if (extension == NULL) {
	    printf("addPartialCertExtensionTpmaOid: X509_EXTENSION_create_by_OBJ failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* append the extensions to the partial certificate stack */
    if (rc == 0) {
	STACK_OF(X509_EXTENSION) *src  = X509v3_add_ext(&partialCertificate->extensions,
							extension,	/* the extension to add */
							-1);		/* location - append */
	if (src == NULL) {
	    printf("addPartialCertExtensionTpmaOid: Error adding oid to extension\n");
	}
    }
    /* append the extensions to the X509 certificate */
    if (rc == 0) {
	int irc = X509_add_ext(x509Certificate,		/* the certificate */
			       extension,		/* the extension to add */
			       -1);			/* location - append */
	if (irc != 1) {
	    printf("addPartialCertExtensionTpmaOid: Error adding oid to extension\n");
	}
    }
    if (extension != NULL) {
	X509_EXTENSION_free(extension);	/* @1 */
    }
    if (object != NULL) {
	ASN1_OBJECT_free(object);	/* @2 */
    }
    if (osData != NULL) {
	ASN1_OCTET_STRING_free(osData);	/* @3 */
    }
    return rc;
}

/* reformCertificate() starts with the X509 certificate filled with the input partialCertificate
   parameter.  It adds the output addedToCertificate and signature values to reform the X509
   certificate that the TPM signed.  */

TPM_RC reformCertificate(X509 			*x509Certificate,
			 TPMI_ALG_HASH		halg,
			 TPMI_ALG_SIG_SCHEME   	scheme,
			 const TPM_ADDTOCERT	*addToCert,
			 TPMT_SIGNATURE 	*tSignature)
{
    TPM_RC 		rc = 0;
    int			irc;
    long		versionl;
    EVP_PKEY 		*evpPubkey = NULL;	/* EVP format public key to be certified */

    /* version */
#if OPENSSL_VERSION_NUMBER < 0x10100000
    /* Older openssl does not has the uint64 function.  This function is deprecated but OK since
       X509 certificates never have a negative version. */
    if (rc == 0) {
	versionl= ASN1_INTEGER_get(addToCert->version);
	if (versionl < 0) {
	    printf("reformCertificate: Error in ASN1_INTEGER_get version\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
#else
    if (rc == 0) {
	uint64_t		version64;
	irc = ASN1_INTEGER_get_uint64(&version64, addToCert->version);
	if (irc != 1) {
	    printf("reformCertificate: Error in ASN1_INTEGER_get_uint64 version\n");
	    rc = TSS_RC_X509_ERROR;
	}
	else if (version64 > LONG_MAX) {
	    printf("reformCertificate: Version out of range\n");
	    rc = TSS_RC_X509_ERROR;
	}
	else {
	    versionl = (long)version64;
	}
    }
#endif
    if (rc == 0) {
	irc = X509_set_version(x509Certificate, versionl);
	if (irc != 1) {
	    printf("reformCertificate: Error in X509_set_version\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* serial number */
    if (rc == 0) {
	irc = X509_set_serialNumber(x509Certificate, addToCert->serialNumber);
	if (irc != 1) {
	    printf("reformCertificate: Error in X509_set_serialNumber\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* public key including algorithm */
    if (rc == 0) {
	evpPubkey = X509_PUBKEY_get(addToCert->key); 	/* freed @1 */
	if (evpPubkey == NULL) {
	    printf("reformCertificate: X509_PUBKEY_get failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    printf("reformCertificate: Error X509_set_pubkey failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add certificate signature */
    if (rc == 0) {
	if (scheme == TPM_ALG_RSASSA) {
	    if (rc == 0) {
		rc = addSignatureRsa(x509Certificate, halg, tSignature);
	    }
	}
	else {	/* scheme == TPM_ALG_ECDSA */
	    if (rc == 0) {
		rc = addSignatureEcc(x509Certificate, halg, tSignature);
	    }
	}
    }
    EVP_PKEY_free(evpPubkey);	/* @1 **/
    return rc;
}

/* addSignatureRsa() copies the TPMT_SIGNATURE output of the TPM2_CertifyX509 command to the X509
   certificate.
 */

TPM_RC addSignatureRsa(X509 		*x509Certificate,
		       TPMI_ALG_HASH	halg,
		       TPMT_SIGNATURE 	*tSignature)
{
    TPM_RC 		rc = 0;
    int 		irc;
    X509_ALGOR 		*signatureAlgorithm = NULL;
    X509_ALGOR 		*certSignatureAlgorithm = NULL;
    ASN1_BIT_STRING 	*asn1Signature = NULL;

    /* FIXME check sign length */

    if (rc == 0) {
	certSignatureAlgorithm = (X509_ALGOR *)X509_get0_tbs_sigalg(x509Certificate);
	X509_get0_signature((OSSLCONST ASN1_BIT_STRING**)&asn1Signature,
			    (OSSLCONST X509_ALGOR **)&signatureAlgorithm,
			    x509Certificate);
    }
    /* set the algorithm in the top level structure */
    /* set the algorithm in the to be signed structure */
    if (rc == 0) {
	switch (halg) {
	  case TPM_ALG_SHA256:
	    X509_ALGOR_set0(signatureAlgorithm,
			    OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
	    X509_ALGOR_set0(certSignatureAlgorithm,
			    OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
	    break;
	  case TPM_ALG_SHA384:
	    X509_ALGOR_set0(signatureAlgorithm,
			    OBJ_nid2obj(NID_sha384WithRSAEncryption), V_ASN1_NULL, NULL);
	    X509_ALGOR_set0(certSignatureAlgorithm,
			    OBJ_nid2obj(NID_sha384WithRSAEncryption), V_ASN1_NULL, NULL);
	    break;
	  default:
	    printf("addSignatureRsa: Unsupported hash algorithm %04x\n", halg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* ASN1_BIT_STRING x509Certificate->signature contains a BIT STRING with the RSA signature */
    if (rc == 0) {
	irc = ASN1_BIT_STRING_set(asn1Signature,
				  tSignature->signature.rsassa.sig.t.buffer,
				  tSignature->signature.rsassa.sig.t.size);
	asn1Signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	asn1Signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	if (irc == 0) {
	    printf("addSignatureRsa: Error in ASN1_BIT_STRING_set for signature\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOECC

/* addSignatureEcc() copies the TPMT_SIGNATURE output of the TPM2_CertifyX509 command to the X509
   certificate.
*/

TPM_RC addSignatureEcc(X509 		*x509Certificate,
		       TPMI_ALG_HASH	halg,
		       TPMT_SIGNATURE 	*tSignature)
{
    TPM_RC 		rc = 0;
    int 		irc;
    X509_ALGOR 		*signatureAlgorithm = NULL;
    X509_ALGOR 		*certSignatureAlgorithm = NULL;
    ASN1_BIT_STRING 	*asn1Signature = NULL;
    BIGNUM 		*rSig = NULL;
    BIGNUM 		*sSig = NULL;
    ECDSA_SIG 		*ecdsaSig = NULL;
    unsigned char 	*ecdsaSigBin = NULL;
    int 		ecdsaSigBinLength;

    /* FIXME check sign length */

    if (rc == 0) {
	certSignatureAlgorithm = (X509_ALGOR *)X509_get0_tbs_sigalg(x509Certificate);
	X509_get0_signature((OSSLCONST ASN1_BIT_STRING**)&asn1Signature,
			    (OSSLCONST X509_ALGOR **)&signatureAlgorithm,
			    x509Certificate);
    }
    /* set the algorithm in the top level structure */
    /* set the algorithm in the to be signed structure */
    if (rc == 0) {
	switch (halg) {
	  case TPM_ALG_SHA256:
	    X509_ALGOR_set0(signatureAlgorithm,
			    OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
	    X509_ALGOR_set0(certSignatureAlgorithm,
			    OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
	    break;
	  case TPM_ALG_SHA384:
	    X509_ALGOR_set0(signatureAlgorithm,
			    OBJ_nid2obj(NID_ecdsa_with_SHA384), V_ASN1_UNDEF, NULL);
	    X509_ALGOR_set0(certSignatureAlgorithm,
			    OBJ_nid2obj(NID_ecdsa_with_SHA384), V_ASN1_UNDEF, NULL);
	    break;
	  default:
	    printf("addSignatureEcc: Unsupported hash algorithm %04x\n", halg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* ASN1_BIT_STRING x509Certificate->signature contains a sequence with two INTEGER, R and S */
    /* construct DER and then ASN1_BIT_STRING_set into X509 */
    if (rc == 0) {
	rSig = BN_new();
	if (rSig == NULL) {
	    printf("addSignatureEcc: BN_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	sSig = BN_new();
	if (sSig == NULL) {
	    printf("addSignatureEcc: BN_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
        rSig = BN_bin2bn(tSignature->signature.ecdsa.signatureR.b.buffer,
			 tSignature->signature.ecdsa.signatureR.b.size, rSig);
        if (rSig == NULL) {
            printf("addSignatureEcc: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    if (rc == 0) {
        sSig = BN_bin2bn(tSignature->signature.ecdsa.signatureS.b.buffer,
			 tSignature->signature.ecdsa.signatureS.b.size, sSig);
        if (sSig == NULL) {
            printf("addSignatureEcc: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    if (rc == 0) {
	ecdsaSig = ECDSA_SIG_new();		/* freed @1 */
	if (ecdsaSig == NULL) {
	    printf("addSignatureEcc: ECDSA_SIG_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = ECDSA_SIG_set0(ecdsaSig, rSig, sSig);
	if (irc != 1) {
	    printf("addSignatureEcc: Error in ECDSA_SIG_set0\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* serialize the signature to DER */
    if (rc == 0) {
	ecdsaSigBinLength = i2d_ECDSA_SIG(ecdsaSig, &ecdsaSigBin);	/* freed @2 */
	if (ecdsaSigBinLength < 0) {
	    printf("addSignatureEcc: Error in signature serialization i2d_ECDSA_SIG()\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add the DER signature to the certificate */
    if (rc == 0) {
	irc = ASN1_BIT_STRING_set(asn1Signature,
				  ecdsaSigBin,
				  ecdsaSigBinLength);
	asn1Signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	asn1Signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;
	if (irc == 0) {
	    printf("addSignatureEcc: Error in ASN1_BIT_STRING_set for signature\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* freed by ECDSA_SIG_free */
    if (ecdsaSig == NULL) {
	BN_free(rSig);
	BN_free(sSig);
    }
    ECDSA_SIG_free(ecdsaSig);		/* @1 */
    OPENSSL_free(ecdsaSigBin);		/* @2 */
    return rc;
}
#endif	/* TPM_TSS_NOECC */

static void printUsage(void)
{
    printf("\n");
    printf("certifyx509\n");
    printf("\n");
    printf("Runs TPM2_Certifyx509\n");
    printf("\n");
    printf("\t-ho\tobject handle\n");
    printf("\t[-pwdo\tpassword for object (default empty)]\n");
    printf("\t-hk\tcertifying key handle\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t[-halg\t(sha256, sha384) (default sha256)]\n");

    printf("\t-rsa keybits\n");
    printf("\t\t2048\n");
    printf("\t\t3072\n");
    printf("\t-ecc curve\n");
    printf("\t\tnistp256\n");
    printf("\t\tnistp384\n");

    printf("\t[-ku\tX509 key usage - string - comma separated, no spaces]\n");
    printf("\t[-iob\tTPMA_OBJECT - 4 byte hex]\n");
    printf("\t\te.g. sign: critical,digitalSignature,keyCertSign,cRLSign (default)\n");
    printf("\t\te.g. decrypt: critical,dataEncipherment,keyAgreement,encipherOnly,decipherOnly\n");
    printf("\t\te.g. fixedTPM: critical,nonRepudiation\n");
    printf("\t\te.g. parent (restrict decrypt): critical,keyEncipherment\n");

    printf("\t[-bit\tbit in partialCertificate to toggle]\n");
    printf("\t[-sub\tsubject same as issuer for self signed (root) certificate]\n");
    printf("\t[-opc\tpartial certificate file name (default do not save)]\n");
    printf("\t[-oa\taddedToCertificate file name (default do not save)]\n");
    printf("\t[-otbs\tsigned tbsDigest file name (default do not save)]\n");
    printf("\t[-os\tsignature file name (default do not save)]\n");
    printf("\t[-ocert\t reconstructed certificate file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);
}

#endif	/* TPM_TSS_MBEDTLS */

#ifdef TPM_TSS_MBEDTLS

int verbose;

int main(int argc, char *argv[])
{
    argc = argc;
    argv = argv;
    printf("certifyx509 not supported with mbedtls yet\n");
    return 0;
}

#endif	/* TPM_TSS_MBEDTLS */
