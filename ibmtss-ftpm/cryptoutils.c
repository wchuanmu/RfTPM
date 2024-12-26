/********************************************************************************/
/*										*/
/*			OpenSSL Crypto Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2022.					*/
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

/* These functions are worthwhile sample code that probably (judgment call) do not belong in the TSS
   library.

   They abstract out crypto library functions.

   They show how to convert public or private EC or RSA among PEM format <-> EVP format <-> EC_KEY
   or RSA format <-> binary arrays <-> TPM format TPM2B_PRIVATE, TPM2B_SENSITIVE, TPM2B_PUBLIC
   usable for loadexternal or import.

   There are functions to convert public keys from TPM <-> RSA, ECC <-> PEM, and to verify a TPM
   signature using a PEM format public key.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#ifndef TPM_TSS_NORSA
#include <openssl/rsa.h>
#endif /* TPM_TSS_NORSA */
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#ifndef TPM_TSS_NOECC
#include <openssl/ec.h>
#endif

#ifndef TPM_TSS_NOFILE
#include <ibmtss/tssfile.h>
#endif
#include <ibmtss/tssutils.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/Implementation.h>

TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
		      TPMI_ALG_HASH hashAlg);

#include "objecttemplates.h"
#include "cryptoutils.h"

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC
static TPM_RC getEcModulusBytes(int	*modulusBytes,
				int	*pointBytes,
				TPMI_ECC_CURVE curveID);
static TPM_RC getEcNid(int		*nid,
		       TPMI_ECC_CURVE 	curveID);
#if OPENSSL_VERSION_NUMBER < 0x30000000
static TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
			 int 		*privateKeyBytes,
			 const EC_KEY 	*ecKey);
#else
static TPM_RC getEcCurveString(const char **curveString,
			       int nid);
static TPM_RC getEccKeyParts(uint8_t **priv,
			     int *privLen,
			     uint8_t **pub,
			     int *pubLen,
			     const EVP_PKEY *eccKey);
static TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
			 int 		*privateKeyBytes,
			 const EVP_PKEY *ecKey);
#endif


#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */

/* verbose tracing flag shared by command line utilities */

int tssUtilsVerbose;

/* openssl compatibility functions, during the transition from 1.0.1, 1.0.2, 1.1.0, 1.1.1.  Some
   structures were made opaque, with gettters and setters.  Some parameters were made const.  Some
   function names changed. */

/* Some functions add const to parameters as of openssl 1.1.0 */

/* These functions are only required for OpenSSL 1.0.  OpenSSL 1.1 has them, and the structures are
   opaque. */

#if OPENSSL_VERSION_NUMBER < 0x10100000

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
	return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL) {
	*pr = sig->r;
    }
    if (ps != NULL) {
	*ps = sig->s;
    }
    return;
}

const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x)
{
    return x->cert_info->signature;
}

void RSA_get0_key(const RSA *rsaKey,
		  const BIGNUM **n,
		  const BIGNUM **e,
		  const BIGNUM **d)
{
    if (n != NULL) {
	*n = rsaKey->n;
    }
    if (e != NULL) {
	*e = rsaKey->e;
    }
    if (d != NULL) {
	*d = rsaKey->d;
    }
    return;
}

void RSA_get0_factors(const RSA *rsaKey,
		      const BIGNUM **p,
		      const BIGNUM **q)
{
    if (p != NULL) {
	*p = rsaKey->p;
    }
    if (q != NULL) {
	*q = rsaKey->q;
    }
    return;
}

static int ossl_x509_set1_time(ASN1_TIME **ptm, const ASN1_TIME *tm);

int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return ossl_x509_set1_time(&x->cert_info->validity->notBefore, tm);
}

int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm)
{
    if (x == NULL)
        return 0;
    return ossl_x509_set1_time(&x->cert_info->validity->notAfter, tm);
}

static int ossl_x509_set1_time(ASN1_TIME **ptm, const ASN1_TIME *tm)
{
    ASN1_TIME *in;
    in = *ptm;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(*ptm);
            *ptm = in;
        }
    }
    return (in != NULL);
}

#endif	/* pre openssl 1.1 */

/* These functions are only required for OpenSSL 1.0.1 OpenSSL 1.0.2 has them, and the structures
   are opaque.   In 1.1.0, the parameters became const.  */

#if OPENSSL_VERSION_NUMBER < 0x10002000

void X509_get0_signature(OSSLCONST ASN1_BIT_STRING **psig,
                         OSSLCONST X509_ALGOR **palg, const X509 *x)
{
    *psig = x->signature;
    *palg = x->sig_alg;
    return;
}

#endif	/* pre openssl 1.0.2 */

#ifndef TPM_TSS_NOFILE

/* getCryptoLibrary() returns a string indicating the underlying crypto library.

   It can be used for programs that must account for library differences.
*/

void getCryptoLibrary(const char **name)
{
    *name = "openssl";
    return;
}
    
/* convertPemToEvpPrivKey() converts a PEM key file to an openssl EVP_PKEY key pair */

TPM_RC convertPemToEvpPrivKey(EVP_PKEY **evpPkey,		/* freed by caller */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	*evpPkey = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, (void *)password);
	if (*evpPkey == NULL) {
	    printf("convertPemToEvpPrivKey: Error reading key file %s\n", pemKeyFilename);
	    rc = TSS_RC_PEM_ERROR;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE

/* convertPemToEvpPubKey() converts a PEM public key file to an openssl EVP_PKEY public key */

TPM_RC convertPemToEvpPubKey(EVP_PKEY **evpPkey,		/* freed by caller */
			     const char *pemKeyFilename)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	*evpPkey = PEM_read_PUBKEY(pemKeyFile, NULL, NULL, NULL);
	if (*evpPkey == NULL) {
	    printf("convertPemToEvpPubKey: Error reading key file %s\n", pemKeyFilename);
	    rc = TSS_RC_PEM_ERROR;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE

/* convertPemToRsaPrivKey() converts a PEM format keypair file to a library specific RSA key
   token.

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC convertPemToRsaPrivKey(void **rsaKey,		/* freed by caller */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @1 */
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	*rsaKey = (void *)PEM_read_RSAPrivateKey(pemKeyFile, NULL, NULL, (void *)password);
#else
	*rsaKey = (void *)PEM_read_PrivateKey(pemKeyFile, NULL, NULL, (void *)password);
#endif
	if (*rsaKey == NULL) {
	    printf("convertPemToRsaPrivKey: Error in OpenSSL PEM_read_RSAPrivateKey()\n");
	    rc = TSS_RC_PEM_ERROR;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

#if OPENSSL_VERSION_NUMBER < 0x30000000

/* convertEvpPkeyToEckey retrieves the EC_KEY key token from the EVP_PKEY */

TPM_RC convertEvpPkeyToEckey(EC_KEY **ecKey,		/* freed by caller */
			     EVP_PKEY *evpPkey)
{
    TPM_RC 	rc = 0;
    
    if (rc == 0) {
	*ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
	if (*ecKey == NULL) {
	    printf("convertEvpPkeyToEckey: Error extracting EC key from EVP_PKEY\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}
#endif

#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */

#if OPENSSL_VERSION_NUMBER < 0x30000000

/* convertEvpPkeyToRsakey() retrieves the RSA key token from the EVP_PKEY */

TPM_RC convertEvpPkeyToRsakey(RSA **rsaKey,		/* freed by caller */
			      EVP_PKEY *evpPkey)
{
    TPM_RC 	rc = 0;
    
    if (rc == 0) {
	*rsaKey = EVP_PKEY_get1_RSA(evpPkey);
	if (*rsaKey == NULL) {
	    printf("convertEvpPkeyToRsakey: EVP_PKEY_get1_RSA failed\n");  
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}
#endif

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivateKeyBin() converts an OpenSSL ECC key token to a binary array

   Only supports NIST P256 and P384 curves.

   For Openssl < 3, ecKey is an EC_KEY structure.
   For Openssl 3, ecKey is an EVP_PKEY,
*/

TPM_RC convertEcKeyToPrivateKeyBin(int 		*privateKeyBytes,
				   uint8_t 	**privateKeyBin,	/* freed by caller */
#if OPENSSL_VERSION_NUMBER < 0x30000000
				   const EC_KEY *ecKey)
#else
    const EVP_PKEY *ecKey)
#endif
{
    TPM_RC 		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    const BIGNUM 	*privateKeyBn = NULL;
    int 		bnBytes;
    if (rc == 0) {
	TPMI_ECC_CURVE curveID;		/* not used */
	rc = getEcCurve(&curveID,
			privateKeyBytes, 
			ecKey);
    }
    /* get the ECC private key as a BIGNUM from the EC_KEY */
    if (rc == 0) {
	privateKeyBn = EC_KEY_get0_private_key(ecKey);
    }
    /* sanity check the BN size against the curve */
    if (rc == 0) {
	bnBytes = BN_num_bytes(privateKeyBn);
	if (bnBytes > *privateKeyBytes) {
	    printf("convertEcKeyToPrivateKeyBin: Error, private key %d bytes too large for curve\n",
		   bnBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* allocate a buffer for the private key array  based on the curve */
    if (rc == 0) {
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key bignum to binary */
    if (rc == 0) {
	/* TPM rev 116 required the ECC private key to be zero padded in the duplicate parameter of
	   import */
	size_t padSize = (size_t)(*privateKeyBytes) - (size_t)bnBytes;
	memset(*privateKeyBin, 0, padSize);
	BN_bn2bin(privateKeyBn, (*privateKeyBin) + padSize);
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPrivateKeyBin:",
					  *privateKeyBin, *privateKeyBytes);
    }
#else
    if (rc == 0) {
	rc = getEccKeyParts(privateKeyBin,		/* freed by caller */
			    privateKeyBytes,
			    NULL,
			    NULL,
			    ecKey);
    }
#endif
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */

/* convertRsaKeyToPrivateKeyBin() converts an OpenSSL RSA key token private prime p to a binary
   array

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC convertRsaKeyToPrivateKeyBin(int 	*privateKeyBytes,
				    uint8_t 	**privateKeyBin,	/* freed by caller */
#if OPENSSL_VERSION_NUMBER < 0x30000000
				    const RSA	*rsaKey)
#else
    const EVP_PKEY *rsaKey)
#endif
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*p = NULL;

    /* get the private primes */
    if (rc == 0) {
	rc = getRsaKeyParts(NULL, NULL, NULL, &p, NULL, rsaKey);	/* freed @2 */
    }
    /* allocate a buffer for the private key array */
    if (rc == 0) {
	*privateKeyBytes = BN_num_bytes(p);
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key bignum to binary */
    if (rc == 0) {
	BN_bn2bin(p, *privateKeyBin);
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    BN_free((BIGNUM *)p);		/* @2 */
#endif
    return rc;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublicKeyBin() converts an OpenSSL EC_KEY public key token to a binary array */

TPM_RC convertEcKeyToPublicKeyBin(int 		*modulusBytes,
				  uint8_t 	**modulusBin,	/* freed by caller */
#if OPENSSL_VERSION_NUMBER < 0x30000000
				  const EC_KEY 	*ecKey)
#else
    const EVP_PKEY 		*ecKey)
#endif
{
    TPM_RC 		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    const EC_POINT 	*ecPoint = NULL;
    const EC_GROUP 	*ecGroup = NULL;

    if (rc == 0) {
	ecPoint = EC_KEY_get0_public_key(ecKey);
	if (ecPoint == NULL) {
	    printf("convertEcKeyToPublicKeyBin: Error extracting EC point from EC public key\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	ecGroup = EC_KEY_get0_group(ecKey);
	if (ecGroup == NULL) {
	    printf("convertEcKeyToPublicKeyBin: Error extracting EC group from EC public key\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the public modulus */
    if (rc == 0) {
	*modulusBytes = (int)EC_POINT_point2oct(ecGroup, ecPoint,
						POINT_CONVERSION_UNCOMPRESSED,
						NULL, 0, NULL);
    }
    if (rc == 0) {
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    if (rc == 0) {
	EC_POINT_point2oct(ecGroup, ecPoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   *modulusBin, *modulusBytes, NULL);
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPublicKeyBin:", *modulusBin, *modulusBytes);
    }
#else
    if (rc == 0) {
	rc = getEccKeyParts(NULL,
			    NULL,
			    modulusBin,		/* freed by caller */
			    modulusBytes,
			    ecKey);
     }
#endif
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */

/* convertRsaKeyToPublicKeyBin() converts from an openssl RSA key token to a public modulus

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC convertRsaKeyToPublicKeyBin(int 		*modulusBytes,
				   uint8_t 	**modulusBin,	/* freed by caller */
				   void 	*rsaKey)
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*n = NULL;

    /* get the public modulus from the RSA key token */
    if (rc == 0) {
	rc = getRsaKeyParts(&n, NULL, NULL, NULL, NULL, rsaKey);
    }
    if (rc == 0) {
	*modulusBytes = BN_num_bytes(n);
    }
    if (rc == 0) {   
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    if (rc == 0) {
	BN_bn2bin(n, *modulusBin);
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    BN_free((BIGNUM *)n);		/* @2 */
#endif
   return rc;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

#if OPENSSL_VERSION_NUMBER >= 0x30000000

/* getEccKeyParts() gets the ECC key parts from an OpenSSL ECC key token.

   For openssl >= 3.0.0, the octet strings are allocated and must be freed.
*/

static TPM_RC getEccKeyParts(uint8_t **priv,	/* freed by caller */
			     int *privLen,
			     uint8_t **pub,	/* freed by caller */
			     int *pubLen,
			     const EVP_PKEY *eccKey)
{
    TPM_RC  	rc = 0;
    int		irc;

    if (priv != NULL) {
	BIGNUM *bnpriv = NULL;	/* freed @1 */
	if (rc == 0) {
	    irc = EVP_PKEY_get_bn_param(eccKey, OSSL_PKEY_PARAM_PRIV_KEY, &bnpriv);
	    if (irc != 1) {
		printf("getEccKeyParts: Error getting priv\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	if (rc == 0) {
	    *privLen = BN_num_bytes(bnpriv);
	    rc = TSS_Malloc(priv, *privLen);
	}
	if (rc == 0) {
	    BN_bn2bin(bnpriv, *priv);
	    BN_free(bnpriv);		/* @1 */
#if 0
	    if (tssUtilsVerbose) TSS_PrintAll("getEccKeyParts: priv",
					      *priv, *privLen);
#endif
	}
    }
    if (pub != NULL) {
	BIGNUM *bnx = NULL;	/* free @1 */
	BIGNUM *bny = NULL;	/* free @2 */
	int 	bnxBytes;
	int 	bnyBytes;
	TPMI_ECC_CURVE 	curveID;	/* not used */
	int 		privateKeyBytes;

	/* the public key is assembled from X and Y.  In openssl 3.0.0, these are bignums and the
	   leading zero can be truncated when converting to bin.  Get the size based on the ECC
	   curve, so that it can be zero padded if necessary. */
	if (rc == 0) {
	    rc = getEcCurve(&curveID,
			    &privateKeyBytes,
			    eccKey);
	}
	/* X point as BIGNUM */
	if (rc == 0) {
	    irc = EVP_PKEY_get_bn_param(eccKey, OSSL_PKEY_PARAM_EC_PUB_X, &bnx);
	    if (irc != 1) {
		printf("getEccKeyParts: Error getting x\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	/* Y point as BIGNUM */
	if (rc == 0) {
	    irc = EVP_PKEY_get_bn_param(eccKey, OSSL_PKEY_PARAM_EC_PUB_Y, &bny);
	    if (irc != 1) {
		printf("getEccKeyParts: Error getting y\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	if (rc == 0) {
	    bnxBytes = BN_num_bytes(bnx);	/* public key point sizes */
	    bnyBytes = BN_num_bytes(bny);
	    /* sanity check against the curve */
	    if ((bnxBytes > privateKeyBytes) ||
		(bnyBytes > privateKeyBytes)) {
		printf("getEccKeyParts: size of X %d or Y %d is greater than private key %d\n",
		       bnxBytes, bnyBytes, privateKeyBytes);
	    }
	}
	/* public key bin is 2x the point size plus 1 for the compression indicator byte */
	if (rc == 0) {
	    *pubLen = privateKeyBytes + privateKeyBytes +1;
	    rc = TSS_Malloc(pub, *pubLen);
	}
	if (rc == 0) {
	    memset(*pub , 0 ,*pubLen);		/* for zero padding */ 
	    (*pub)[0] = 0x04; 			/* uncompressed */
	    /* convert to bin, normally the entire point, but occasionally have to add the zero
	       pad */
	    BN_bn2bin(bnx, (*pub) + 1 + privateKeyBytes - bnxBytes);
	    BN_bn2bin(bny, (*pub) + 1 + privateKeyBytes + privateKeyBytes - bnyBytes);
	    BN_free(bnx);		/* @1 */
	    BN_free(bny);		/* @2 */
#if 0
	    if (tssUtilsVerbose) TSS_PrintAll("getEccKeyParts: pub",
					      *pub, *pubLen);
#endif
	}
    }
    return rc;
}

#endif

/* convertEcPrivateKeyBinToPrivate() converts an EC 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE

*/

TPM_RC convertEcPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				       TPM2B_SENSITIVE 	*objectSensitive,
				       int 		privateKeyBytes,
				       uint8_t 		*privateKeyBin,
				       const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertEcPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = TSS_RC_NULL_PARAMETER;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */	

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_ECC;
	tSensitive.seedValue.b.size = 0;
	/* key password converted to TPM2B */
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.ecc.t.buffer)) {
	    printf("convertEcPrivateKeyBinToPrivate: Error, private key size %u not 32\n",
		   privateKeyBytes);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.ecc.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.ecc.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */	
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}	
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif 	/* TPM_TSS_NOECC */
#endif 	/* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaPrivateKeyBinToPrivate() converts an RSA prime 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE

*/

TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					TPM2B_SENSITIVE *objectSensitive,
					int 		privateKeyBytes,
					uint8_t 	*privateKeyBin,
					const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertRsaPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = TSS_RC_NULL_PARAMETER;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */	

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_RSA;
	/* generate a seed for storage keys */
	tSensitive.seedValue.b.size = 32; 	/* FIXME hard coded seed length */
	rc = TSS_RandBytes(tSensitive.seedValue.b.buffer, tSensitive.seedValue.b.size);
    }
    /* key password converted to TPM2B */
    if (rc == 0) {
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.rsa.t.buffer)) {
	    printf("convertRsaPrivateKeyBinToPrivate: "
		   "Error, private key modulus %d greater than %lu\n",
		   privateKeyBytes, (unsigned long)sizeof(tSensitive.sensitive.rsa.t.buffer));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.rsa.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.rsa.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */	
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}	
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif /* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPublicKeyBinToPublic() converts an EC modulus and other parameters to a TPM2B_PUBLIC

*/

TPM_RC convertEcPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
				     int			keyType,
				     TPMI_ALG_SIG_SCHEME 	scheme,
				     TPMI_ALG_HASH 		nalg,
				     TPMI_ALG_HASH		halg,
				     TPMI_ECC_CURVE 		curveID,
				     int 			modulusBytes,
				     uint8_t 			*modulusBin)
{
    TPM_RC 	rc = 0;
    int		pointBytes;
    int		curveModulusBytes;

    scheme = scheme;	/* scheme parameter not supported yet */
     if (rc == 0) {
	 rc = getEcModulusBytes(&curveModulusBytes, &pointBytes, curveID);
     }
     if (rc == 0) {
	if (modulusBytes != curveModulusBytes) {
	    printf("convertEcPublicKeyBinToPublic: public modulus expected %u bytes, actual %u\n",
		   curveModulusBytes, modulusBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_ECC;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDH;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	objectPublic->publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
	objectPublic->publicArea.parameters.eccDetail.curveID = curveID;	
	objectPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	objectPublic->publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;

	objectPublic->publicArea.unique.ecc.x.t.size = pointBytes;	
	memcpy(objectPublic->publicArea.unique.ecc.x.t.buffer,
	       modulusBin +1, pointBytes);	

	objectPublic->publicArea.unique.ecc.y.t.size = pointBytes;	
	memcpy(objectPublic->publicArea.unique.ecc.y.t.buffer,
	       modulusBin +1 + pointBytes, pointBytes);	
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif	/* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaPublicKeyBinToPublic() converts a public modulus to a TPM2B_PUBLIC structure. */

TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
				      int			keyType,
				      TPMI_ALG_SIG_SCHEME 	scheme,
				      TPMI_ALG_HASH 		nalg,
				      TPMI_ALG_HASH		halg,
				      int 			modulusBytes,
				      uint8_t 			*modulusBin)
{
    TPM_RC 		rc = 0;

    if (rc == 0) {
	if ((size_t)modulusBytes > sizeof(objectPublic->publicArea.unique.rsa.t.buffer)) {
	    printf("convertRsaPublicKeyBinToPublic: Error, "
		   "public key modulus %d greater than %lu\n", modulusBytes,
		   (unsigned long)sizeof(objectPublic->publicArea.unique.rsa.t.buffer));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_RSA;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = scheme;
	objectPublic->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	objectPublic->publicArea.parameters.rsaDetail.keyBits = modulusBytes * 8;	
	objectPublic->publicArea.parameters.rsaDetail.exponent = 0;

	objectPublic->publicArea.unique.rsa.t.size = modulusBytes;
	memcpy(objectPublic->publicArea.unique.rsa.t.buffer, modulusBin, modulusBytes);
    }
    return rc;
}

#endif	/* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivate() converts an openssl EC_KEY to token to either a TPM2B_PRIVATE or
   TPM2B_SENSITIVE
*/

TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
			     TPM2B_SENSITIVE 	*objectSensitive,
#if OPENSSL_VERSION_NUMBER < 0x30000000
			     EC_KEY 		*ecKey,
#else
			     EVP_PKEY 		*ecKey,
#endif
			     const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an openssl EC_KEY token to a binary array */
    if (rc == 0) {
	rc = convertEcKeyToPrivateKeyBin(&privateKeyBytes,
					 &privateKeyBin,	/* freed @1 */
					 ecKey);
    }
    if (rc == 0) {
	rc = convertEcPrivateKeyBinToPrivate(objectPrivate,
					     objectSensitive,
					     privateKeyBytes,
					     privateKeyBin,
					     password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaKeyToPrivate() converts an openssl RSA key token to either a TPM2B_PRIVATE or
   TPM2B_SENSITIVE

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
			      TPM2B_SENSITIVE 	*objectSensitive,
#if OPENSSL_VERSION_NUMBER < 0x30000000
			      RSA		*rsaKey,
#else
			      EVP_PKEY 		*rsaKey,
#endif
			      const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an openssl RSA key token private prime p to a binary array */
    if (rc == 0) {
	rc = convertRsaKeyToPrivateKeyBin(&privateKeyBytes,
					  &privateKeyBin,	/* freed @1 */
					  rsaKey);
    }
    /* convert an RSA prime 'privateKeyBin' to either a TPM2B_PRIVATE or a TPM2B_SENSITIVE */
    if (rc == 0) {
	rc = convertRsaPrivateKeyBinToPrivate(objectPrivate,
					      objectSensitive,
					      privateKeyBytes,
					      privateKeyBin,
					      password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#endif /* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublic() converts an EC_KEY to a TPM2B_PUBLIC */

TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
			    int				keyType,
			    TPMI_ALG_SIG_SCHEME 	scheme,
			    TPMI_ALG_HASH 		nalg,
			    TPMI_ALG_HASH		halg,
#if OPENSSL_VERSION_NUMBER < 0x30000000
			    EC_KEY 			*ecKey)
#else
    EVP_PKEY 		*ecKey)
#endif
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;
    TPMI_ECC_CURVE	curveID;
    int 		privateKeyBytes;

    if (rc == 0) {
	rc = convertEcKeyToPublicKeyBin(&modulusBytes,
					&modulusBin,		/* freed @1 */
					ecKey);
    }
    if (rc == 0) {
	rc = getEcCurve(&curveID, &privateKeyBytes, ecKey);
    }
    if (rc == 0) {
	rc = convertEcPublicKeyBinToPublic(objectPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   curveID,
					   modulusBytes,
					   modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif 	/* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaKeyToPublic() converts from an openssl RSA key token to a TPM2B_PUBLIC

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     void 			*rsaKey)
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;
    
    /* openssl RSA key token to a public modulus */
    if (rc == 0) {
	rc = convertRsaKeyToPublicKeyBin(&modulusBytes,
					 &modulusBin,		/* freed @1 */
					 rsaKey);
    }
    /* public modulus to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaPublicKeyBinToPublic(objectPublic,
					    keyType,
					    scheme,
					    nalg,
					    halg,
					    modulusBytes,
					    modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}

#endif /* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToKeyPair() converts a PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertEcPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_PRIVATE 		*objectPrivate,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename,
			     const char 		*password)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY 	*ecKey = NULL;
#else
    EVP_PKEY 	*ecKey = NULL;
#endif

    /* convert a PEM file to an openssl EVP_PKEY */
    if (rc == 0) {
	rc = convertPemToEvpPrivKey(&evpPkey,		/* freed @1 */
				    pemKeyFilename,
				    password);
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @2 */
				   evpPkey);
#else
	/* openssl 3.0.0 and up use the EVP_PKEY directly */
	ecKey = evpPkey;
#endif
    }
    if (rc == 0) {
	rc = convertEcKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				   NULL,		/* TPM2B_SENSITIVE */
				   ecKey,
				   password);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY_free(ecKey);   		/* @2 */
#endif
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */
#endif  /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToPublic() converts an ECC signing public key in PEM format to a
   TPM2B_PUBLIC */

TPM_RC convertEcPemToPublic(TPM2B_PUBLIC 	*objectPublic,
			    int			keyType,
			    TPMI_ALG_SIG_SCHEME scheme,
			    TPMI_ALG_HASH 	nalg,
			    TPMI_ALG_HASH	halg,
			    const char		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY  	*evpPkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY 	*ecKey = NULL;
#else
    EVP_PKEY 	*ecKey = NULL;
#endif

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @2 */
				   evpPkey);
#else
	/* openssl 3.0.0 and up use the EVP_PKEY directly */
	ecKey = evpPkey;
#endif
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);   		/* @2 */
    }
#endif
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */
#endif  /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaPemToKeyPair() converts an RSA PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_PRIVATE 		*objectPrivate,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char 		*pemKeyFilename,
			      const char 		*password)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA		*rsaKey = NULL;
#else
    EVP_PKEY 	*rsaKey = NULL;
#endif

    if (rc == 0) {
	rc = convertPemToEvpPrivKey(&evpPkey,		/* freed @1 */
				    pemKeyFilename,
				    password);
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
#else
	/* openssl 3.0.0 and up use the EVP_PKEY directly */
	rsaKey = evpPkey;
#endif
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				    NULL,		/* TPM2B_SENSITIVE */
				    rsaKey,
				    password);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    TSS_RsaFree(rsaKey);		/* @2 */
#endif
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcDerToKeyPair() converts an EC keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertEcDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_SENSITIVE 		*objectSensitive,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename,
			     const char 		*password)
{
    TPM_RC		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY		*ecKey = NULL;
#else
    EVP_PKEY 		*ecKey = NULL;
#endif
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
#if OPENSSL_VERSION_NUMBER < 0x30000000
	ecKey = d2i_ECPrivateKey(NULL, &tmpPtr, (long)derSize);	/* freed @2 */
#else
	ecKey = d2i_PrivateKey(EVP_PKEY_EC, NULL,
				&tmpPtr, (long)derSize);
#endif
	if (ecKey == NULL) {
	    printf("convertEcDerToKeyPair: could not convert key to EC_KEY\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertEcKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				   objectSensitive,	/* TPM2B_SENSITIVE */
				   ecKey,
				   password);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    free(derBuffer);		/* @1 */
    TSS_EccFree(ecKey);		/* @2 */
    return rc;
}

/* convertEcDerToPublic() converts an EC public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

TPM_RC convertEcDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			    int				keyType,
			    TPMI_ALG_SIG_SCHEME 	scheme,
			    TPMI_ALG_HASH 		nalg,
			    TPMI_ALG_HASH		halg,
			    const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
    EVP_PKEY 		*evpPkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY		*ecKey = NULL;
#else
    EVP_PKEY 		*ecKey = NULL;
#endif
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
	evpPkey = d2i_PUBKEY(NULL, &tmpPtr, (long)derSize);	/* freed @2 */
	if (evpPkey == NULL) {
	    printf("convertEcDerToPublic: could not convert key to EVP_PKEY\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @3 */
				   evpPkey);
#else
	/* openssl 3.0.0 and up use the EVP_PKEY directly */
	ecKey = evpPkey;
#endif
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    free(derBuffer);			/* @1 */
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @2 */
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY_free(ecKey);   		/* @3 */
#endif
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */
#endif  /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaDerToKeyPair() converts an RSA keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertRsaDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_SENSITIVE 		*objectSensitive,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char		*derKeyFilename,
			      const char 		*password)
{
    TPM_RC		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA 		*rsaKey = NULL;
#else
    EVP_PKEY 		*rsaKey = NULL;
#endif
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rsaKey = d2i_RSAPrivateKey(NULL, &tmpPtr, (long)derSize);	/* freed @2 */
#else
	rsaKey = d2i_PrivateKey(EVP_PKEY_RSA, NULL,
				&tmpPtr, (long)derSize);
#endif
	if (rsaKey == NULL) {
	    printf("convertRsaDerToKeyPair: could not convert key to RSA\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				    objectSensitive,	/* TPM2B_SENSITIVE */
				    rsaKey,
				    password);	
    }	
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    free(derBuffer);			/* @1 */
    TSS_RsaFree(rsaKey);		/* @2 */
    return rc;
}

/* convertRsaDerToPublic() converts an RSA public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

TPM_RC convertRsaDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA 		*rsaKey = NULL;
#else
    EVP_PKEY 		*rsaKey = NULL;
#endif
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rsaKey = d2i_RSA_PUBKEY(NULL, &tmpPtr, (long)derSize);	/* freed @2 */
#else
	rsaKey = d2i_PUBKEY(NULL, &tmpPtr, (long)derSize);
#endif
	if (rsaKey == NULL) {
	    printf("convertRsaDerToPublic: could not convert key to RSA\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    free(derBuffer);			/* @1 */
    TSS_RsaFree(rsaKey);		/* @2 */
    return rc;
}

/* convertRsaPemToPublic() converts an RSA public key in PEM format to a TPM2B_PUBLIC */

TPM_RC convertRsaPemToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA		*rsaKey = NULL;
#else
    EVP_PKEY 	*rsaKey = NULL;
#endif

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
#else
	/* openssl 3.0.0 and up use the EVP_PKEY directly */
	rsaKey = evpPkey;
#endif
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    TSS_RsaFree(rsaKey);		/* @2 */
#endif
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */ 
#endif /* TPM_TSS_NOFILE */

/* getRsaKeyParts() gets the RSA key parts from an OpenSSL RSA key token.

   If n is not NULL, returns n, e, and d.  If p is not NULL, returns p and q.

   For openssl < 3.0.0, the bignums are references to the RSA key and should not be freed separately.

   For openssl >= 3.0.0, the bignums are allocated and must be freed.
*/

TPM_RC getRsaKeyParts(const BIGNUM **n,
		      const BIGNUM **e,
		      const BIGNUM **d,
		      const BIGNUM **p,
		      const BIGNUM **q,
#if OPENSSL_VERSION_NUMBER < 0x30000000
		      const RSA *rsaKey)
#else
    const EVP_PKEY *rsaKey)
#endif
{
    TPM_RC  	rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (n != NULL) {
	RSA_get0_key(rsaKey, n, e, d);
    }
    if (p != NULL) {
	RSA_get0_factors(rsaKey, p, q);
    }
#else
    int		irc;
    if (rc == 0) {
	if (n != NULL) {
	    irc = EVP_PKEY_get_bn_param(rsaKey, OSSL_PKEY_PARAM_RSA_N, (BIGNUM **)n);
	    if (irc != 1) {
		printf("getRsaKeyParts: Error getting n\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
	    }
	}
    }
    if (rc == 0) {
	if (e != NULL) {
	    irc = EVP_PKEY_get_bn_param(rsaKey, OSSL_PKEY_PARAM_RSA_E, (BIGNUM **)e);
	    if (irc != 1) {
		printf("getRsaKeyParts: Error getting e\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
	    }
	}
    }
    if (rc == 0) {
	if (d != NULL) {
	    irc = EVP_PKEY_get_bn_param(rsaKey, OSSL_PKEY_PARAM_RSA_D, (BIGNUM **)d);
	    if (irc != 1) {
		printf("getRsaKeyParts: Error getting d\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
	    }
	}
    }
    if (rc == 0) {
	if (p != NULL) {
	    irc = EVP_PKEY_get_bn_param(rsaKey, OSSL_PKEY_PARAM_RSA_FACTOR1, (BIGNUM **)p);
	    if (irc != 1) {
		printf("getRsaKeyParts: Error getting p\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
	    }
	}
    }
    if (rc == 0) {
	if (q != NULL) {
	    irc = EVP_PKEY_get_bn_param(rsaKey, OSSL_PKEY_PARAM_RSA_FACTOR2, (BIGNUM **)q);
	    if (irc != 1) {
		printf("getRsaKeyParts: Error getting q\n");
		rc = TSS_RC_RSA_KEY_CONVERT;
	    }
	}
    }
#endif
    return rc;
}

/* returns the type (EVP_PKEY_RSA or EVP_PKEY_EC) of the EVP_PKEY.

 */

int getRsaPubkeyAlgorithm(EVP_PKEY *pkey)
{
    int 			pkeyType;	/* RSA or EC */
    pkeyType = EVP_PKEY_base_id(pkey);
    return pkeyType;
}

#ifndef TPM_TSS_NOFILE

/* convertPublicToPEM() saves a PEM format public key from a TPM2B_PUBLIC
 
*/

TPM_RC convertPublicToPEM(const TPM2B_PUBLIC *inPublic,
			  const char *pemFilename)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPubkey = NULL;          	/* OpenSSL public key, EVP format */

    /* convert TPM2B_PUBLIC to EVP_PKEY */
    if (rc == 0) {
	switch (inPublic->publicArea.type) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSA:
	    rc = convertRsaPublicToEvpPubKey(&evpPubkey,	/* freed @1 */
					     &inPublic->publicArea.unique.rsa);
	    break;
#endif /* TPM_TSS_NORSA */
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECC:
	    rc = convertEcTPMTPublicToEvpPubKey(&evpPubkey,		/* freed @1 */
						&inPublic->publicArea);
	    break;
#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */
	  default:
	    printf("convertPublicToPEM: Unknown publicArea.type %04hx unsupported\n",
		   inPublic->publicArea.type);
	    rc = TSS_RC_NOT_IMPLEMENTED;
	    break;
	}
    }
    /* write the openssl structure in PEM format */
    if (rc == 0) {
	rc = convertEvpPubkeyToPem(evpPubkey,
				   pemFilename);

    }
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);		/* @1 */
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NORSA

/* convertRsaPublicToEvpPubKey() converts an RSA TPM2B_PUBLIC to a EVP_PKEY.

*/

TPM_RC convertRsaPublicToEvpPubKey(EVP_PKEY **evpPubkey,	/* freed by caller */
				   const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa)
{
    TPM_RC 	rc = 0;
    /* public exponent */
    unsigned char earr[3] = {0x01, 0x00, 0x01};
#if OPENSSL_VERSION_NUMBER < 0x30000000
    int		irc;
    RSA		*rsaPubKey = NULL;
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	*evpPubkey = EVP_PKEY_new();		/* freed by caller */
	if (*evpPubkey == NULL) {
	    printf("convertRsaPublicToEvpPubKey: EVP_PKEY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* TPM to RSA token */
    if (rc == 0) {
	/* For Openssl < 3, rsaKey is an RSA structure. */
	/* For Openssl 3, rsaKey is an EVP_PKEY. */
	rc = TSS_RSAGeneratePublicTokenI
	     ((void **)&rsaPubKey,		/* freed by caller  */
	      tpm2bRsa->t.buffer,  		/* public modulus */
	      tpm2bRsa->t.size,
	      earr,      			/* public exponent */
	      sizeof(earr));
    }
    /* RSA token to EVP */
    if (rc == 0) {
	irc  = EVP_PKEY_assign_RSA(*evpPubkey, rsaPubKey);
	if (irc == 0) {
	    TSS_RsaFree(rsaPubKey);	/* because not assigned to EVP_PKEY */
	    printf("convertRsaPublicToEvpPubKey: EVP_PKEY_assign_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
#else
    /* TPM to RSA token */
    if (rc == 0) {
	/* For Openssl < 3, rsaKey is an RSA structure. */
	/* For Openssl 3, rsaKey is an EVP_PKEY. */
	rc = TSS_RSAGeneratePublicTokenI
	     ((void **)evpPubkey,		/* freed by caller  */
	      tpm2bRsa->t.buffer,  		/* public modulus */
	      tpm2bRsa->t.size,
	      earr,      			/* public exponent */
	      sizeof(earr));
    }
#endif
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

#if OPENSSL_VERSION_NUMBER < 0x30000000

/* convertEcPublicToEvpPubKey() converts an EC TPMS_ECC_POINT to an EVP_PKEY.

   Deprecated: This is hard coded to NIST P256.  See convertEcTPMTPublicToEvpPubKey().
 */

TPM_RC convertEcPublicToEvpPubKey(EVP_PKEY **evpPubkey,		/* freed by caller */
				  const TPMS_ECC_POINT *tpmsEccPoint)
{
    TPM_RC 	rc = 0;
    int		irc;
    EC_GROUP 	*ecGroup = NULL;
    EC_KEY 	*ecKey = NULL;
    BIGNUM 	*x = NULL;		/* freed @2 */
    BIGNUM 	*y = NULL;		/* freed @3 */
    
    if (rc == 0) {
	ecKey = EC_KEY_new();		/* freed @1 */
	if (ecKey == NULL) {
	    printf("convertEcPublicToEvpPubKey: Error creating EC_KEY\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);	/* freed @4 */
	if (ecGroup == NULL) {
	    printf("convertEcPublicToEvpPubKey: Error in EC_GROUP_new_by_curve_name\an");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	/* returns void */
	EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);
    }
    /* assign curve to EC_KEY */
    if (rc == 0) {
	irc = EC_KEY_set_group(ecKey, ecGroup);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: Error in EC_KEY_set_group\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	rc = convertBin2Bn(&x,				/* freed @2 */
			   tpmsEccPoint->x.t.buffer,
			   tpmsEccPoint->x.t.size);	
    }
    if (rc == 0) {
	rc = convertBin2Bn(&y,				/* freed @3 */
			   tpmsEccPoint->y.t.buffer,
			   tpmsEccPoint->y.t.size);
    }
    if (rc == 0) {
	irc = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: "
		   "Error converting public key from X Y to EC_KEY format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	*evpPubkey = EVP_PKEY_new();		/* freed by caller */
	if (*evpPubkey == NULL) {
	    printf("convertEcPublicToEvpPubKey: EVP_PKEY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_set1_EC_KEY(*evpPubkey, ecKey);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: "
		   "Error converting public key from EC to EVP format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (ecGroup != NULL) {
	EC_GROUP_free(ecGroup);	/* @4 */
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);	/* @1 */
    }
    if (x != NULL) {
	BN_free(x);		/* @2 */
    }
    if (y != NULL) {
	BN_free(y);		/* @3 */
    }
    return rc;
}

#endif

/* convertEcTPMTPublicToEvpPubKey() converts an EC TPMT_PUBLIC to an EVP_PKEY.  The only items used
   from the TPMT_PUBLIC are the curveID and X and Y points.

   This is the replacement for convertEcPublicToEvpPubKey().
 */

TPM_RC convertEcTPMTPublicToEvpPubKey(EVP_PKEY **evpPubkey,		/* freed by caller */
				      const TPMT_PUBLIC *tpmtPublic)
{
    TPM_RC 	rc = 0;
    int		irc;
    BIGNUM 	*x = NULL;		/* freed @1 */
    BIGNUM 	*y = NULL;		/* freed @2 */
    int		nid;
    EC_GROUP 	*ecGroup = NULL;	/* freed @4 */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    EC_KEY 	*ecKey = NULL;		/* freed @3 */
#else
    EC_POINT		*ecPoint = NULL;
    uint8_t		*pubBin = NULL;	/* freed @7 */
    size_t		pubBinLength;
    EVP_PKEY_CTX 	*ctx = NULL;		/* freed @5 */
    OSSL_PARAM_BLD 	*param_bld = NULL;	/* freed @8 */
    OSSL_PARAM 		*params = NULL;		/* freed @6 */
    const char 		*curveString = NULL;
#endif
    if (rc == 0) {
	rc = convertBin2Bn(&x,				/* freed @1 */
			   tpmtPublic->unique.ecc.x.t.buffer,
			   tpmtPublic->unique.ecc.x.t.size);
    }
    if (rc == 0) {
	rc = convertBin2Bn(&y,				/* freed @2 */
			   tpmtPublic->unique.ecc.y.t.buffer,
			   tpmtPublic->unique.ecc.y.t.size);
    }
    /* map from the TCG curve to the openssl nid */
    if (rc == 0) {
	rc = getEcNid(&nid, tpmtPublic->parameters.eccDetail.curveID);
    }
    if (rc == 0) {
	ecGroup = EC_GROUP_new_by_curve_name(nid);	/* freed @4 */
	if (ecGroup == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: Error in EC_GROUP_new_by_curve_name\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	ecKey = EC_KEY_new();				/* freed @3 */
	if (ecKey == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: Error creating EC_KEY\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	/* returns void */
	EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);
    }
    /* assign curve to EC_KEY */
    if (rc == 0) {
	irc = EC_KEY_set_group(ecKey, ecGroup);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: Error in EC_KEY_set_group\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error converting public key from X Y to EC_KEY format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	*evpPubkey = EVP_PKEY_new();		/* freed by caller */
	if (*evpPubkey == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: EVP_PKEY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_set1_EC_KEY(*evpPubkey, ecKey);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error converting public key from EC to EVP format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
#else
    /* see EVP_PKEY-EC.html for constants */
    if (rc == 0) {
	ecPoint = EC_POINT_new(ecGroup);		/* freed @4 */
	if (ecPoint== NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: EC_POINT_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EC_POINT_set_affine_coordinates(ecGroup, ecPoint, x, y, NULL);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error converting public key from X Y to EC_KEY format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	pubBinLength = EC_POINT_point2buf(ecGroup, ecPoint,
					  POINT_CONVERSION_COMPRESSED,
					  &pubBin, NULL);	/* freed @7 */
	if (pubBinLength == 0) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error in EC_POINT_point2buf\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	param_bld = OSSL_PARAM_BLD_new();		/* freed @8 */
	if (param_bld == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey; "
		   "Error in OSSL_PARAM_BLD_new\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	rc = getEcCurveString(&curveString, nid);
    }
    if (rc == 0) {
	irc = OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
					      curveString, 0);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey; "
		   "Error in OSSL_PARAM_BLD_push_utf8_string\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
					       pubBin, pubBinLength);
  	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey; "
		   "Error in OSSL_PARAM_BLD_push_utf8_string\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	params = OSSL_PARAM_BLD_to_param(param_bld);		/* freed @6 */
	if (params == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error in OSSL_PARAM_BLD_to_param()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);	/* freed @5 */
	if (ctx == NULL) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error in EVP_PKEY_CTX_new_from_name()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_fromdata_init(ctx);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error in EVP_PKEY_fromdata_init()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_fromdata(ctx, evpPubkey,			/* freed by caller */
				EVP_PKEY_PUBLIC_KEY, params);
	if (irc != 1) {
	    printf("convertEcTPMTPublicToEvpPubKey: "
		   "Error in EVP_PKEY_fromdata()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
#endif
    BN_free(x);			/* @1 */
    BN_free(y);			/* @2 */
    EC_GROUP_free(ecGroup);	/* @4 */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);	/* @3 */
    }
#else
    OSSL_PARAM_BLD_free(param_bld);;	/* @8 */
    OSSL_PARAM_free(params); 		/* @6 */
    EVP_PKEY_CTX_free(ctx);		/* @5 */
    OPENSSL_free(pubBin);		/* @7 */
#endif
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif  /* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE

TPM_RC convertEvpPubkeyToPem(EVP_PKEY *evpPubkey,
			     const char *pemFilename)
{
    TPM_RC 	rc = 0;
    int		irc;
    FILE 	*pemFile = NULL; 
    
    if (rc == 0) {
	pemFile = fopen(pemFilename, "wb");	/* close @1 */
	if (pemFile == NULL) {
	    printf("convertEvpPubkeyToPem: Unable to open PEM file %s for write\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	irc = PEM_write_PUBKEY(pemFile, evpPubkey);
	if (irc == 0) {
	    printf("convertEvpPubkeyToPem: Unable to write PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);			/* @1 */
    }
    return rc;
}

#endif
#ifndef TPM_TSS_NOFILE

/* verifySignatureFromPem() verifies the signature 'tSignature' against the digest 'message' using
   the public key in the PEM format file 'pemFilename'.

*/

TPM_RC verifySignatureFromPem(unsigned char *message,
			      unsigned int messageSize,
			      TPMT_SIGNATURE *tSignature,
			      TPMI_ALG_HASH halg,
			      const char *pemFilename)
{
    TPM_RC 		rc = 0;
    EVP_PKEY 		*evpPkey = NULL;        /* OpenSSL public key, EVP format */
#ifdef TPM_TSS_NORSA
    halg = halg;
#endif /* TPM_TSS_NORSA */

    /* read the public key from PEM format */
    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1*/
				   pemFilename);
    }
    /* RSA or EC */
    if (rc == 0) {
	switch(tSignature->sigAlg) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSASSA:
	  case TPM_ALG_RSAPSS:
	    rc = verifyRSASignatureFromEvpPubKey(message,
						 messageSize,
						 tSignature,
						 halg,
						 evpPkey);
	    break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECDSA:
	    rc = verifyEcSignatureFromEvpPubKey(message,
						messageSize,
						tSignature,
						evpPkey);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("verifySignatureFromPem: Unknown signature algorithm %04x\n", tSignature->sigAlg);
	    rc = TSS_RC_BAD_SIGNATURE_ALGORITHM;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif

#ifndef TPM_TSS_NORSA

/* verifyRSASignatureFromEvpPubKey() verifies the signature 'tSignature' against the digest
   'message' using the RSA public key in evpPkey.

*/

TPM_RC verifyRSASignatureFromEvpPubKey(unsigned char *message,
				       unsigned int messageSize,
				       TPMT_SIGNATURE *tSignature,
				       TPMI_ALG_HASH halg,
				       EVP_PKEY *evpPkey)
{
    TPM_RC 		rc = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA 		*rsaPubKey = NULL;	/* OpenSSL public key, RSA format */

    /* construct the RSA key token */
    if (rc == 0) {
	rsaPubKey = EVP_PKEY_get1_RSA(evpPkey);	/* freed @1 */
	if (rsaPubKey == NULL) {
	    printf("verifyRSASignatureFromEvpPubKey: EVP_PKEY_get1_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
#else
    EVP_PKEY *rsaPubKey = evpPkey;
#endif
    if (rc == 0) {
	rc = verifyRSASignatureFromRSA(message,
				       messageSize,
				       tSignature,
				       halg,
				       rsaPubKey);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    TSS_RsaFree(rsaPubKey);          	/* @1 */
#endif
    return rc;
}

/* signRSAFromRSA() signs digest to signature, using rsaKey. 

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC signRSAFromRSA(uint8_t *signature, size_t *signatureLength,
		      size_t signatureSize,
		      const uint8_t *digest, size_t digestLength,
		      TPMI_ALG_HASH hashAlg,
		      void *rsaKey)
{
    TPM_RC 		rc = 0;
    int			irc;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    int			nid;			/* openssl hash algorithm */

    /* map the hash algorithm to the openssl NID */
    if (rc == 0) {
	switch (hashAlg) {
#ifndef TPM_TSS_NODEPRECATEDALGS
	  case TPM_ALG_SHA1:
	    nid = NID_sha1;
	    break;
#endif
	  case TPM_ALG_SHA256:
	    nid = NID_sha256;
	    break;
	  case TPM_ALG_SHA384:
	    nid = NID_sha384;
	    break;
	  case TPM_ALG_SHA512:
	    nid = NID_sha512;
	    break;
	  default:
	    printf("signRSAFromRSA: Error, hash algorithm %04hx unsupported\n", hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* validate that the length of the resulting signature will fit in the
       signature array */
    if (rc == 0) {
	unsigned int keySize = RSA_size(rsaKey);
	if (keySize > signatureSize) {
	    printf("signRSAFromRSA: Error, private key length %u > signature buffer %u\n",
		   keySize, (unsigned int)signatureSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	unsigned int siglen;
	irc = RSA_sign(nid,
		       digest, (unsigned int)digestLength,
		       signature, &siglen,
		       rsaKey);
	*signatureLength = siglen;
	if (irc != 1) {
	    printf("signRSAFromRSA: Error in OpenSSL RSA_sign()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
#else
    EVP_PKEY_CTX 	*ctx = NULL;
    const EVP_MD 	*md = NULL;

    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new(rsaKey, NULL);		/* freed @1 */
	if (ctx == NULL) {
	    printf("signRSAFromRSA: Error in EVP_PKEY_CTX_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_sign_init(ctx);
	if (irc != 1) {
	    printf("signRSAFromRSA: Error in EVP_PKEY_sign_init()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, hashAlg);
    }
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_signature_md(ctx, md);
	if (irc <= 0) {
	    printf("signRSAFromRSA: Error in EVP_PKEY_CTX_set_signature_md()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	if (irc <= 0) {
	    printf("signRSAFromRSA: Error in EVP_PKEY_CTX_set_rsa_padding()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	size_t siglen = signatureSize;
	irc = EVP_PKEY_sign(ctx,
			    signature,  &siglen,
			    digest, (unsigned int)digestLength);
	*signatureLength = siglen;
	if (irc != 1) {
	    printf("signRSAFromRSA: Error in EVP_PKEY_sign()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    EVP_PKEY_CTX_free(ctx);	/* @1 */
#endif
    return rc;
}

/* verifyRSASignatureFromRSA() verifies the signature 'tSignature' against the digest 'message'
   using the RSA public key in the OpenSSL EVP_PKEY or RSA format.

   Supports RSASSA and RSAPSS schemes.

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC verifyRSASignatureFromRSA(unsigned char *message,
				 unsigned int messageSize,
				 TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH halg,
				 void *rsaPubKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    const EVP_MD 	*md = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    int 		nid = 0;	/* initialized these two to suppress false gcc -O3
					   warnings */
    /* map from hash algorithm to openssl nid */
    if (rc == 0) {
	switch (halg) {
#ifndef TPM_TSS_NODEPRECATEDALGS
	  case TPM_ALG_SHA1:
	    nid = NID_sha1;
	    md = EVP_sha1();
	    break;
#endif
	  case TPM_ALG_SHA256:
	    nid = NID_sha256;
	    md = EVP_sha256();
	    break;
	  case TPM_ALG_SHA384:
	    nid = NID_sha384;
	    md = EVP_sha384();
	    break;
	  case TPM_ALG_SHA512:
	    nid = NID_sha512;
	    md = EVP_sha512();
	    break;
	  default:
	    printf("verifyRSASignatureFromRSA: Unknown hash algorithm %04x\n", halg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* verify the signature */
    if (tSignature->sigAlg == TPM_ALG_RSASSA) {
	if (rc == 0) {
	    irc = RSA_verify(nid,
			     message, messageSize,
			     tSignature->signature.rsassa.sig.t.buffer,
			     tSignature->signature.rsassa.sig.t.size,
			     rsaPubKey);
	    if (irc != 1) {
		printf("verifyRSASignatureFromRSA: Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else if (tSignature->sigAlg == TPM_ALG_RSAPSS) {
	uint8_t decryptedSig[sizeof(tSignature->signature.rsapss.sig.t.buffer)];
	if (rc == 0) {
	    irc = RSA_public_decrypt(tSignature->signature.rsapss.sig.t.size,
				     tSignature->signature.rsapss.sig.t.buffer,
				     decryptedSig,
				     rsaPubKey,
				     RSA_NO_PADDING);
	    if (irc == -1) {
		printf("verifyRSASignatureFromRSA: RSAPSS Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
	if (rc == 0) {
	    irc = RSA_verify_PKCS1_PSS(rsaPubKey,
				       message,
				       md,
				       decryptedSig,
				       -2); /* salt length recovered from signature*/
	    if (irc != 1) {
		printf("verifyRSASignatureFromRSA: RSAPSS Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else {
	printf("verifyRSASignatureFromRSA: Bad signature scheme %04x\n",
	       tSignature->sigAlg);
	rc = TSS_RC_RSA_SIGNATURE;
    }
#else
    EVP_PKEY_CTX 	*ctx = NULL;

    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new(rsaPubKey, NULL);	/* freed @1 */
	if (ctx == NULL) {
	    printf("verifyRSAFSignatureromRSA: Error in EVP_PKEY_CTX_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify_init(ctx);
	if (irc != 1) {
	    printf("verifyRSASignatureFromRSA: Error in EVP_PKEY_verify_init()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, halg);
    }
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_signature_md(ctx, md);
	if (irc <= 0) {
	    printf("verifyRSASignatureFromRSA: Error in EVP_PKEY_CTX_set_signature_md()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	if (tSignature->sigAlg == TPM_ALG_RSASSA) {
	    irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	}
	else if (tSignature->sigAlg == TPM_ALG_RSAPSS) {
	    irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
	}
	else {
	    rc = TSS_RC_RSA_SIGNATURE;
	    	printf("verifyRSASignatureFromRSA: Bad signature scheme %04x\n",
		       tSignature->sigAlg);
	}
    }
    if (rc == 0) {
	if (irc <= 0) {
	    printf("verifyRSASignatureFromRSA: Error in EVP_PKEY_CTX_set_rsa_padding()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify(ctx,
			      tSignature->signature.rsapss.sig.t.buffer,
			      tSignature->signature.rsapss.sig.t.size,
			      message, messageSize);
 	if (irc != 1) {
	    printf("verifyRSASignatureFromRSA: Error in EVP_PKEY_verify()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    EVP_PKEY_CTX_free(ctx);	/* @1 */
#endif
   return rc;
}

/* verifyRSASignatureFromRSA3() verifies the signature 'tSignature' against the digest 'message'
   using the RSA public key in the OpenSSL EVP_PKEY format.

   Supports RSASSA and RSAPSS schemes.

   rsaPubKey is an EVP_PKEY,

   Differs from verifyRSASignatureFromRSA3(), where the public key is openssl version dependent.
*/

TPM_RC verifyRSASignatureFromRSA3(const unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  void *rsaPubKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    const EVP_MD 	*md = NULL;
    EVP_PKEY_CTX 	*ctx = NULL;

    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new(rsaPubKey, NULL);	/* freed @1 */
	if (ctx == NULL) {
	    printf("verifyRSAFSignatureromRSA3: Error in EVP_PKEY_CTX_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify_init(ctx);
	if (irc != 1) {
	    printf("verifyRSASignatureFromRSA3: Error in EVP_PKEY_verify_init()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, halg);
    }
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_signature_md(ctx, md);
	if (irc <= 0) {
	    printf("verifyRSASignatureFromRSA3: Error in EVP_PKEY_CTX_set_signature_md()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	if (tSignature->sigAlg == TPM_ALG_RSASSA) {
	    irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	}
	else if (tSignature->sigAlg == TPM_ALG_RSAPSS) {
	    irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
	}
	else {
	    rc = TSS_RC_RSA_SIGNATURE;
	    printf("verifyRSASignatureFromRSA3: Bad signature scheme %04x\n",
		   tSignature->sigAlg);
	}
    }
    if (rc == 0) {
	if (irc <= 0) {
	    printf("verifyRSASignatureFromRSA3: Error in EVP_PKEY_CTX_set_rsa_padding()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify(ctx,
			      tSignature->signature.rsapss.sig.t.buffer,
			      tSignature->signature.rsapss.sig.t.size,
			      message, messageSize);
 	if (irc != 1) {
	    printf("verifyRSASignatureFromRSA3: Error in EVP_PKEY_verify()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    EVP_PKEY_CTX_free(ctx);	/* @1 */
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* verifyEcSignatureFromEvpPubKey() verifies the signature 'tSignature' against the digest 'message'
   using the EC public key in evpPkey.

*/

TPM_RC verifyEcSignatureFromEvpPubKey(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      EVP_PKEY *evpPkey)
{
    TPM_RC 		rc = 0;
    int			irc;
    BIGNUM 		*r = NULL;
    BIGNUM 		*s = NULL;
    ECDSA_SIG 		*ecdsaSig = NULL;
    uint8_t 		*signature = NULL;
    int 		signatureSize;
    EVP_PKEY_CTX 	*ctx = NULL;

    /* construct the ECDSA_SIG signature token */
    if (rc == 0) {
	rc = convertBin2Bn(&r,			/* freed @2 */
			   tSignature->signature.ecdsa.signatureR.t.buffer,
			   tSignature->signature.ecdsa.signatureR.t.size);
    }
    if (rc == 0) {
	rc = convertBin2Bn(&s,			/* freed @2 */
			   tSignature->signature.ecdsa.signatureS.t.buffer,
			   tSignature->signature.ecdsa.signatureS.t.size);
    }
    /* ECDSA_SIG_new() allocates an empty ECDSA_SIG structure.  */
    if (rc == 0) {
	ecdsaSig = ECDSA_SIG_new(); 		/* freed @2 */
	if (ecdsaSig == NULL) {
	    printf("verifyEcSignatureFromEvpPubKey: Error creating ECDSA_SIG_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	int irc = ECDSA_SIG_set0(ecdsaSig, r, s);
	if (irc != 1) {
            printf("verifyEcSignatureFromEvpPubKey: Error in ECDSA_SIG_set0()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* serialize the signature */
    if (rc == 0) {
	signatureSize = i2d_ECDSA_SIG(ecdsaSig, &signature);	/* freed @3 */
	if (signatureSize < 0) {
	    printf("verifyEcSignatureFromEvpPubKey: Signature serialization failed\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new(evpPkey, NULL);	/* freed @1 */
	if (ctx == NULL) {
	    printf("verifyEcSignatureFromEvpPubKey: Error in EVP_PKEY_CTX_new()\n");
	    rc =TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify_init(ctx);
	if (irc != 1) {
	    printf("verifyEcSignatureFromEvpPubKey: Error in EVP_PKEY_verify_init()\n");
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_verify(ctx,
			      signature, signatureSize,
			      message, messageSize);
	if (irc != 1) {
	    printf("verifyEcSignatureFromEvpPubKey: Error in EVP_PKEY_verify()\n");
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    EVP_PKEY_CTX_free(ctx);		/* @1 */
    OPENSSL_free(signature);		/* @3 */
    /* if the ECDSA_SIG was allocated correctly, r and s are implicitly freed */
    if (ecdsaSig != NULL) {
	ECDSA_SIG_free(ecdsaSig);	/* @2 */
    }
    /* if not, explicitly free */
    else {
	if (r != NULL) BN_free(r);	/* @2 */
	if (s != NULL) BN_free(s);	/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOFILE

/* verifySignatureFromHmacKey() verifies the signature (MAC) against the digest 'message'
   using the HMAC key in raw binary format.
*/

TPM_RC verifySignatureFromHmacKey(unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  const char *hmacKeyFilename)
{
    TPM_RC 		rc = 0;
    TPM2B_KEY 		hmacKey;
    uint32_t 		sizeInBytes;
    
    /* read the HMAC key */
    if (rc == 0) {
	rc = TSS_File_Read2B(&hmacKey.b,
			     sizeof(hmacKey.t.buffer),
			     hmacKeyFilename);
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(halg);
	rc = TSS_HMAC_Verify(&tSignature->signature.hmac,
			     &hmacKey,		/* input HMAC key */
			     sizeInBytes,
			     messageSize, message,
			     0, NULL);
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* convertRsaBinToTSignature() converts an RSA binary signature to a TPMT_SIGNATURE */

TPM_RC convertRsaBinToTSignature(TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH halg,
				 const uint8_t *signatureBin,
				 size_t signatureBinLen)
{
    TPM_RC rc = 0;

    /* check that the signature size agrees with the TPMT_SIGNATURE  */
    if (rc == 0) {
	size_t signatureBinMax = sizeof(((TPMS_SIGNATURE_RSA *)NULL)->sig.t.buffer);
	if (signatureBinLen > signatureBinMax) {
	    printf("convertRsaBinToTSignature: signature length %lu greater than %lu\n",
		   (unsigned long)signatureBinLen, (unsigned long)signatureBinMax);
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	tSignature->sigAlg = TPM_ALG_RSASSA;
	tSignature->signature.rsassa.hash = halg;
	tSignature->signature.rsassa.sig.t.size = (uint16_t)signatureBinLen;
	memcpy(&tSignature->signature.rsassa.sig.t.buffer, signatureBin, signatureBinLen);
    }
    return rc;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcBinToTSignature() converts an EC binary signature to a TPMT_SIGNATURE */

TPM_RC convertEcBinToTSignature(TPMT_SIGNATURE *tSignature,
				TPMI_ALG_HASH halg,
				const uint8_t *signatureBin,
				size_t signatureBinLen)
{
    TPM_RC rc = 0;
    ECDSA_SIG 		*ecSig = NULL;
    uint16_t		rBytes;
    uint16_t 		sBytes;
    const BIGNUM 	*pr = NULL;
    const BIGNUM 	*ps = NULL;
    
    if (rc == 0) {
	tSignature->sigAlg = TPM_ALG_ECDSA;
	tSignature->signature.ecdsa.hash = halg;
    }
    /* convert DER to ECDSA_SIG */
    if (rc == 0) {
	ecSig = d2i_ECDSA_SIG(NULL, &signatureBin, (long)signatureBinLen);	/* freed @1 */
	if (ecSig == NULL) {
	    printf("convertEcBinToTSignature: could not convert signature to ECDSA_SIG\n");
	    rc = TPM_RC_VALUE;
	}
    }
    /* check that the signature size agrees with the currently hard coded P256 curve */
    if (rc == 0) {
	ECDSA_SIG_get0(ecSig, &pr, &ps);
	rBytes = (uint16_t)BN_num_bytes(pr);
	sBytes = (uint16_t)BN_num_bytes(ps);
	if ((rBytes > sizeof(tSignature->signature.ecdsa.signatureR.t.buffer)) ||
	    (sBytes > sizeof(tSignature->signature.ecdsa.signatureS.t.buffer))) {
	    printf("convertEcBinToTSignature: signature rBytes %u or sBytes %u greater than %u\n",
		   rBytes, sBytes,
		   (unsigned int)sizeof(tSignature->signature.ecdsa.signatureR.t.buffer));
	    rc = TPM_RC_VALUE;
	}
    }
    /* extract the raw signature bytes from the openssl structure BIGNUMs */
    if (rc == 0) {
	tSignature->signature.ecdsa.signatureR.t.size = rBytes;
	tSignature->signature.ecdsa.signatureS.t.size = sBytes;

	BN_bn2bin(pr, (unsigned char *)&tSignature->signature.ecdsa.signatureR.t.buffer);
	BN_bn2bin(ps, (unsigned char *)&tSignature->signature.ecdsa.signatureS.t.buffer);
	if (tssUtilsVerbose) {
	    TSS_PrintAll("convertEcBinToTSignature: signature R",
			 tSignature->signature.ecdsa.signatureR.t.buffer,
			 tSignature->signature.ecdsa.signatureR.t.size);		
	    TSS_PrintAll("convertEcBinToTSignature: signature S",
			 tSignature->signature.ecdsa.signatureS.t.buffer,
			 tSignature->signature.ecdsa.signatureS.t.size);		
	}
    }
    if (ecSig != NULL) {
	ECDSA_SIG_free(ecSig);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOECC

/* getEcCurve() gets the TCG algorithm ID curve associated with the openssl EC_KEY.  Gets the length
   of the private key (in bytes).
*/

#if OPENSSL_VERSION_NUMBER < 0x30000000

static TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
			 int 		*privateKeyBytes, 
			 const EC_KEY 	*ecKey)
{
    TPM_RC 		rc = 0;
    const EC_GROUP 	*ecGroup;
    int			nid;

    if (rc == 0) {
	ecGroup = EC_KEY_get0_group(ecKey);
	nid = EC_GROUP_get_curve_name(ecGroup);	/* openssl NID */
	/* NID to TCG curve ID */
	switch (nid) {
	  case NID_X9_62_prime256v1:
	    *curveID = TPM_ECC_NIST_P256;
	    *privateKeyBytes = 32;
	    break;
	  case NID_secp384r1:
	    *curveID = TPM_ECC_NIST_P384;
	    *privateKeyBytes = 48;
	    break;
	  default:
	    printf("getEcCurve: Error, curve NID %u not supported \n", nid);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}

#else

static TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
			 int 		*privateKeyBytes,
			 const EVP_PKEY *ecKey)
{
    TPM_RC  	rc = 0;
    int		irc;
    char 	curveName[64];

    if (rc == 0) {
	irc = EVP_PKEY_get_utf8_string_param(ecKey, OSSL_PKEY_PARAM_GROUP_NAME,
					     curveName, sizeof(curveName), NULL);
	if (irc != 1) {
	    printf("getEcCurve: Error getting curve\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* FIXME make table */
    if (rc == 0) {
	if (strcmp(curveName, "prime256v1") == 0) {
	    *curveID = TPM_ECC_NIST_P256;
	    *privateKeyBytes = 32;
	}
	else if (strcmp(curveName, "secp384r1") == 0) {
	    *curveID = TPM_ECC_NIST_P384;
	    *privateKeyBytes = 48;
	}
	else {
	    printf("getEcCurve: Error, curve %s not supported \n", curveName);
	    rc = TSS_RC_EC_KEY_CONVERT;

	}
    }
    return rc;
}

/* getEcCurveString() maps the TPM curve ID to the openssl utf-8 string */

static TPM_RC getEcCurveString(const char **curveString,
			       int nid)
{
    TPM_RC  	rc = 0;

    *curveString = OBJ_nid2sn(nid);
    if (*curveString == NULL) {
	printf("getEcCurveString: Error, nid %d not supported \n", nid);
	rc = TSS_RC_EC_KEY_CONVERT;
   }
    return rc;
}

#endif

/* getEcNid() gets the OpenSSL nid corresponding to the TCG algorithm ID curve */

static TPM_RC getEcNid(int		*nid,
		       TPMI_ECC_CURVE 	curveID)
{
    TPM_RC 		rc = 0;

    switch (curveID) {
      case TPM_ECC_NIST_P192:
	*nid = NID_X9_62_prime192v1;	/* untested guess */
	break;
      case TPM_ECC_NIST_P224:
	*nid = NID_secp224r1;		/* untested guess */
	break;
      case TPM_ECC_NIST_P256:		/* TCG standard */
	*nid = NID_X9_62_prime256v1;
	break;
      case TPM_ECC_NIST_P384:		/* TCG standard */
	*nid = NID_secp384r1;
	break;
      case TPM_ECC_NIST_P521:
	*nid = NID_secp521r1;		/* untested guess */
	break;
      case TPM_ECC_BN_P256:
      case TPM_ECC_BN_P638:
      case TPM_ECC_SM2_P256:
      case TPM_ECC_BP_P256_R1:
      case TPM_ECC_BP_P384_R1:
      case TPM_ECC_BP_P512_R1:
      case TPM_ECC_CURVE_25519:
      default:
	*nid = NID_undef;
	printf("getEcNid: Error, TCG curve %04x not supported \n", curveID);
	rc = TSS_RC_EC_KEY_CONVERT;
    }
    return rc;
}

/* getEcModulusBytes() gets the modulus size and bytes on the point corresponding to the TCG
   algorithm ID curve */

static TPM_RC getEcModulusBytes(int	*modulusBytes,
				int	*pointBytes,
				TPMI_ECC_CURVE curveID)
{
    TPM_RC 		rc = 0;

    /* add 1 byte for point compression */
    switch (curveID) {
      case TPM_ECC_NIST_P192:
	*pointBytes = 24;
	*modulusBytes = 49;		/* 1+24+24 untested guess */
	break;
      case TPM_ECC_NIST_P224:
	*pointBytes = 28;
	*modulusBytes = 57;		/* 1+28+28 untested guess */
	break;
      case TPM_ECC_NIST_P256:
	*pointBytes = 32;
	*modulusBytes = 65;		/* 1+32+32 TCG standard */
	break;
      case TPM_ECC_NIST_P384:
	*pointBytes = 48;
	*modulusBytes = 97;		/* 1+48+48 TCG standard */
	break;
      case TPM_ECC_NIST_P521:
      case TPM_ECC_BN_P256:
      case TPM_ECC_BN_P638:
      case TPM_ECC_SM2_P256:
      case TPM_ECC_BP_P256_R1:
      case TPM_ECC_BP_P384_R1:
      case TPM_ECC_BP_P512_R1:
      case TPM_ECC_CURVE_25519:
      default:
	*modulusBytes = 0;
	printf("getEcModulusBytes: Error, TCG curve %04x not supported \n", curveID);
	rc = TSS_RC_EC_KEY_CONVERT;
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif

/* convertBin2Bn() wraps the openSSL function in an error handler

   Converts a char array to bignum
*/

TPM_RC convertBin2Bn(BIGNUM **bn,			/* freed by caller */
		     const unsigned char *bin,
		     unsigned int bytes)
{
    TPM_RC rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    
       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            printf("convertBin2Bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

