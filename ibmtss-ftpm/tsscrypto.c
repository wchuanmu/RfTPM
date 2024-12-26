/********************************************************************************/
/*										*/
/*			     TSS Library Dependent Crypto Support		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		ECC Salt functions written by Bill Martin			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2023.					*/
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

/* Interface to OpenSSL version 1.0.2, 1.1.1, 3.n crypto library */

#include <string.h>
#include <stdio.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#ifndef TPM_TSS_NORSA
#include <openssl/rsa.h>
#endif
#include <openssl/rand.h>
#include <openssl/engine.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <ibmtss/tssresponsecode.h>
#include "tssproperties.h"
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssmarshal.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

LIB_EXPORT
TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
		      TPMI_ALG_HASH hashAlg);

extern int tssVverbose;
extern int tssVerbose;

/* openssl compatibility code */

#if OPENSSL_VERSION_NUMBER < 0x10101000
#define EC_POINT_set_affine_coordinates(a,b,c,d,e)  EC_POINT_set_affine_coordinates_GFp(a,b,c,d,e)
#define EC_POINT_get_affine_coordinates(a,b,c,d,e)  EC_POINT_get_affine_coordinates_GFp(a,b,c,d,e)
#endif

/* local prototypes */

static TPM_RC TSS_Hash_GetOsslString(const char **str, TPMI_ALG_HASH hashAlg);
#if OPENSSL_VERSION_NUMBER >=  0x30000000
static TPM_RC TSS_AES_CFB(EVP_CIPHER_CTX **ctx,
			  uint32_t keySizeInBits,
			  uint8_t *key,
			  uint8_t *iv,
			  int encrypt);
#endif


#ifndef TPM_TSS_NOECC

/* ECC salt */

static TPM_RC TSS_bn2binpad(unsigned char *bin, int binlen, const BIGNUM *bn);
static TPM_RC TSS_ECC_GeneratePlatformEphemeralKey(BIGNUM 	**ephPrivKey,
						   BIGNUM 	**ephPubX,
						   BIGNUM 	**ephPubY,
						   EC_GROUP 	*ecGroup,
						   int 		curveID);
static TPM_RC TSS_BN_new(BIGNUM **bn);

#endif	/* TPM_TSS_NOECC */

static TPM_RC TSS_bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes);

/*
  Initialization
*/

TPM_RC TSS_Crypto_Init(void)
{
    TPM_RC		rc = 0;
#if 0
    int			irc;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms();
#endif
#if 0
    irc = FIPS_mode_set(1);
    if (irc == 0) {
	if (tssVerbose) printf("TSS_Crypto_Init: Cannot set FIPS mode\n");
    }
#endif
    return rc;
}

/*
  Digests
*/

/* TSS_Hash_GetString() maps from the TCG hash algorithm to the OpenSSL string */

static TPM_RC TSS_Hash_GetOsslString(const char **str, TPMI_ALG_HASH hashAlg)
{
    TPM_RC	rc = 0;

    switch (hashAlg) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	*str = "sha1";
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	*str = "sha256";
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	*str = "sha384";
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	*str = "sha512";
	break;
#endif
      default:
	*str = NULL;
	rc = TSS_RC_BAD_HASH_ALGORITHM;
    }
    return rc;
}

TPM_RC TSS_Hash_GetMd(const EVP_MD **md,
		      TPMI_ALG_HASH hashAlg)
{
    TPM_RC		rc = 0;
    const char 		*str = NULL; 

    if (rc == 0) {
	rc =  TSS_Hash_GetOsslString(&str, hashAlg);
    }
    if (rc == 0) {
	*md = EVP_get_digestbyname(str);	/* no free needed */
	if (*md == NULL) {
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_HMAC_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				const TPM2B_KEY *hmacKey,
				va_list ap)
{
    TPM_RC		rc = 0;
    int 		irc = 0;
    int			done = FALSE;
    uint8_t 		*buffer;	/* segment to hash */
    int			length;		/* segment to hash */
#if OPENSSL_VERSION_NUMBER < 0x10100000	
    HMAC_CTX 		ctx;
    const EVP_MD 	*md = NULL;	/* message digest method */
#elif OPENSSL_VERSION_NUMBER < 0x30000000
    HMAC_CTX 		*ctx = NULL;
    const EVP_MD 	*md = NULL;	/* message digest method */
#else
    EVP_MAC 		*mac = NULL;
    EVP_MAC_CTX 	*ctx = NULL;
    const char 		*algString = NULL;
    OSSL_PARAM 		params[2];
    size_t		outLength;
#endif

    /* initialize the HMAC context */
#if OPENSSL_VERSION_NUMBER < 0x10100000
    HMAC_CTX_init(&ctx);
#elif OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	ctx = HMAC_CTX_new();
	if (ctx == NULL) {
	    if (tssVerbose) printf("TSS_Hash_Generate_valist: HMAC_CTX_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
#else
    if (rc == 0) {
	mac = EVP_MAC_fetch(NULL, "hmac", NULL);	/* freed @2 */
	if (mac == NULL) {
	    if (tssVerbose) printf("TSS_Hash_Generate_valist: EVP_MAC_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	ctx = EVP_MAC_CTX_new(mac);			/* freed @1 */
	if (ctx == NULL) {
	    if (tssVerbose) printf("TSS_Hash_Generate_valist: EVP_MAC_CTX_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
#endif

    /* get the message digest */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
    }
#else
    /* map algorithm to string */
    if (rc == 0) {
	rc =  TSS_Hash_GetOsslString(&algString, digest->hashAlg);
    }
#endif

    /* initialize the MAC context */
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	irc = HMAC_Init_ex(&ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key */
			   md,					/* message digest method */
			   NULL);
#elif OPENSSL_VERSION_NUMBER < 0x30000000
	irc = HMAC_Init_ex(ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key */
			   md,					/* message digest method */
			   NULL);
#else
	params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)algString, 0);
	params[1] = OSSL_PARAM_construct_end();
	irc = EVP_MAC_init(ctx,
			   hmacKey->b.buffer, hmacKey->b.size,	/* HMAC key */
			   params);				/* message digest method */
#endif

	if (irc != 1) {
	    if (tssVerbose) printf("TSS_HMAC_Generate: HMAC Init failed\n");
	    rc = TSS_RC_HMAC;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_HMAC_Generate: Length is negative\n");
		rc = TSS_RC_HMAC;
	    }
	    else {
#if OPENSSL_VERSION_NUMBER < 0x10100000
		irc = HMAC_Update(&ctx, buffer, length);
#elif OPENSSL_VERSION_NUMBER < 0x30000000
		irc = HMAC_Update(ctx, buffer, length);
#else
		irc = EVP_MAC_update(ctx, buffer, length);
#endif
		if (irc != 1) {
		    if (tssVerbose) printf("TSS_HMAC_Generate: HMAC Update failed\n");
		    rc = TSS_RC_HMAC;
		}
	    }
 	}
	else {
	    done = TRUE;
	}
    }
    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	irc = HMAC_Final(&ctx, (uint8_t *)&digest->digest, NULL);
#elif OPENSSL_VERSION_NUMBER < 0x30000000
	irc = HMAC_Final(ctx, (uint8_t *)&digest->digest, NULL);
#else
	irc = EVP_MAC_final(ctx, (uint8_t *)&digest->digest,  &outLength, sizeof(digest->digest));
#endif
	if (irc == 0) {
	    if (tssVerbose) printf("TSS_HMAC_Generate: HMAC Final failed\n");
	    rc = TSS_RC_HMAC;
	}
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000
    HMAC_CTX_cleanup(&ctx);
#elif OPENSSL_VERSION_NUMBER < 0x30000000
    HMAC_CTX_free(ctx);
#else
    EVP_MAC_CTX_free(ctx);		/* @1 */
    EVP_MAC_free(mac);			/* @2 */
#endif
    return rc;
}

/*
  valist is int length, unsigned char *buffer pairs
  
  length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate_valist(TPMT_HA *digest,		/* largest size of a digest */
				va_list ap)
{
    TPM_RC		rc = 0;
    int			irc = 0;
    int			done = FALSE;
    int			length;
    uint8_t 		*buffer;
    EVP_MD_CTX 		*mdctx;
    const EVP_MD 	*md;

    if (rc == 0) {
	mdctx = EVP_MD_CTX_create();
        if (mdctx == NULL) {
	    if (tssVerbose) printf("TSS_Hash_Generate: EVP_MD_CTX_create failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
    }
    if (rc == 0) {
	irc = EVP_DigestInit_ex(mdctx, md, NULL);
	if (irc != 1) {
	    rc = TSS_RC_HASH;
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, int);		/* first vararg is the length */
	buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	if (buffer != NULL) {			/* loop until a NULL buffer terminates */
	    if (length < 0) {
		if (tssVerbose) printf("TSS_Hash_Generate: Length is negative\n");
		rc = TSS_RC_HASH;
	    }
	    else {
		/* if (tssVverbose) TSS_PrintAll("TSS_Hash_Generate:", buffer, length); */
		if (length != 0) {
		    EVP_DigestUpdate(mdctx, buffer, length);
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }
    if (rc == 0) {
	EVP_DigestFinal_ex(mdctx, (uint8_t *)&digest->digest, NULL);
    }
    EVP_MD_CTX_destroy(mdctx);
    return rc;
}

/* Random Numbers */

TPM_RC TSS_RandBytes(unsigned char *buffer, uint32_t size)
{
    TPM_RC 	rc = 0;
    int		irc = 0;

    irc = RAND_bytes(buffer, size);
    if (irc != 1) {
	if (tssVerbose) printf("TSS_RandBytes: Random number generation failed\n");
	rc = TSS_RC_RNG_FAILURE;
    }
    return rc;
}

/*
  RSA functions
*/

#ifndef TPM_TSS_NORSA

/* TSS_RsaNew() allocates an openssl RSA key token.

   This abstracts the crypto library specific allocation.

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

TPM_RC TSS_RsaNew(void **rsaKey)
{
    TPM_RC  	rc = 0;

    /* sanity check for the free */
    if (rc == 0) {
	if (*rsaKey != NULL) {
            if (tssVerbose)
		printf("TSS_RsaNew: Error (fatal), token %p should be NULL\n",
		       *rsaKey);
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* construct the OpenSSL private key object */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
        *rsaKey = RSA_new();                        	/* freed by caller */
        if (*rsaKey == NULL) {
            if (tssVerbose) printf("TSS_RsaNew: Error in RSA_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
        }
    }
#else
    if (rc == 0) {
	*rsaKey = EVP_PKEY_new();
        if (*rsaKey == NULL) {
            if (tssVerbose) printf("TSS_RsaNew: Error in EVP_PKEY_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
        }
    }
    if (rc == 0) {
    }
#endif
    return rc;
}

/* TSS_RsaFree() frees an openssl RSA key token.

   This abstracts the crypto library specific free.

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

void TSS_RsaFree(void *rsaKey)
{
    if (rsaKey != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
        RSA_free(rsaKey); 
#else
	EVP_PKEY_free(rsaKey);
#endif
    }
    return;
}

/* TSS_RSAGeneratePublicToken() is deprecated for application use, since it is openssl library
   dependent.

   Use TSS_RSAGeneratePublicTokenI().
*/

#ifndef TPM_TSS_NODEPRECATED

TPM_RC TSS_RSAGeneratePublicToken(RSA **rsa_pub_key,		/* freed by caller */
				  const unsigned char *narr,    /* public modulus */
				  uint32_t nbytes,
				  const unsigned char *earr,    /* public exponent */
				  uint32_t ebytes)
{
    TPM_RC  	rc = 0;
    rc = TSS_RSAGeneratePublicTokenI((void **)rsa_pub_key,
				     narr, 
				     nbytes,
				     earr,
				     ebytes);
    return rc;
}

#endif /* TPM_TSS_NODEPRECATED */

/* TSS_RSAGeneratePublicTokenI() generates an RSA key token from n and e

   Free rsa_pub_key using TSS_RsaFree();

   For Openssl < 3, rsaKey is an RSA structure.
   For Openssl 3, rsaKey is an EVP_PKEY.
 */

TPM_RC TSS_RSAGeneratePublicTokenI(void **rsa_pub_key,		/* freed by caller */
				   const unsigned char *narr,   /* public modulus */
				   uint32_t nbytes,
				   const unsigned char *earr,   /* public exponent */
				   uint32_t ebytes)
{
    TPM_RC  	rc = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    int 	irc;
#endif
    BIGNUM *    n = NULL;
    BIGNUM *    e = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA **	rsaPubKey = (RSA **)rsa_pub_key;	/* openssl specific structure */
#else
    EVP_PKEY_CTX 	*ctx = NULL;
    OSSL_PARAM_BLD 	*param_bld = NULL;
    OSSL_PARAM 		*params = NULL; 
#endif

    /* construct the OpenSSL private key object */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	rc = TSS_RsaNew(rsa_pub_key);		/* freed by caller */
    }
#endif
    if (rc == 0) {
        rc = TSS_bin2bn(&n, narr, nbytes);	/* freed by caller, < 3.0.0 */
    }						/* freed @4, 3.0.0 */
    if (rc == 0) {
        rc = TSS_bin2bn(&e, earr, ebytes);	/* freed by caller, < 3.0.0  */
    }						/* freed @5, 3.0.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000
    if (rc == 0) {
        (*rsaPubKey)->n = n;
        (*rsaPubKey)->e = e;
        (*rsaPubKey)->d = NULL;
    }
#elif OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	irc = RSA_set0_key(*rsaPubKey, n, e, NULL);
	if (irc != 1) {
            if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: Error in RSA_set0_key()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
#else
    /* See EVP_PKEY-RSA for parameter values */
    if (rc == 0) {
	param_bld = OSSL_PARAM_BLD_new();		/* freed @2 */
	if (param_bld == NULL) {
            if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: Error in OSSL_PARAM_BLD_new()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = OSSL_PARAM_BLD_push_BN(param_bld, "n", n);
	if (irc != 1) {
            if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in OSSL_PARAM_BLD_push_BN()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = OSSL_PARAM_BLD_push_BN(param_bld, "e", e);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in OSSL_PARAM_BLD_push_BN()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	params = OSSL_PARAM_BLD_to_param(param_bld);	/* freed @3 */
	if (params == NULL) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in OSSL_PARAM_BLD_to_param()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);		/* freed @1 */
	if (ctx == NULL) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in EVP_PKEY_CTX_new_from_name()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_fromdata_init(ctx);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in EVP_PKEY_fromdata_init()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_fromdata(ctx, (EVP_PKEY **)rsa_pub_key,		/* freed by caller */
				EVP_PKEY_PUBLIC_KEY, params);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_RSAGeneratePublicTokenI: "
				   "Error in EVP_PKEY_fromdata()\n");
            rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    OSSL_PARAM_free(params);		/* @3 */
    OSSL_PARAM_BLD_free(param_bld);	/* @2 */
    EVP_PKEY_CTX_free(ctx);		/* @1 */
    /* for openssl < 3.0.0, n and e are part of the RSA structure, freed with it.  For 3.0.0 and up,
       they're copied to the EVP_PKEY, so the parts are freed here. */
    BN_free(n);				/* @4 */
    BN_free(e);				/* @5 */
#endif
    return rc;
}

/* TSS_RSAPublicEncrypt() pads 'decrypt_data' to 'encrypt_data_size' and encrypts using the public
   key 'n, e'.
*/

TPM_RC TSS_RSAPublicEncrypt(unsigned char *encrypt_data,    /* encrypted data */
			    size_t encrypt_data_size,       /* size of encrypted data buffer */
			    const unsigned char *decrypt_data,      /* decrypted data */
			    size_t decrypt_data_size,
			    unsigned char *narr,           /* public modulus */
			    uint32_t nbytes,
			    unsigned char *earr,           /* public exponent */
			    uint32_t ebytes,
			    unsigned char *p,		/* encoding parameter */
			    int pl,
			    TPMI_ALG_HASH halg)		/* OAEP hash algorithm */
{
    TPM_RC  	rc = 0;
    int         irc;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA         *rsa_pub_key = NULL;
#else
    EVP_PKEY 	*rsa_pub_key = NULL;
    EVP_PKEY_CTX 	*ctx = NULL;
#endif
    unsigned char *padded_data = NULL;
 
    if (tssVverbose) printf(" TSS_RSAPublicEncrypt: Input data size %lu\n",
			    (unsigned long)decrypt_data_size);
    /* intermediate buffer for the decrypted but still padded data */
    if (rc == 0) {
        rc = TSS_Malloc(&padded_data, (uint32_t)encrypt_data_size);               /* freed @2 */
    }
    /* construct the OpenSSL public key object */
    if (rc == 0) {
	/* For Openssl < 3, rsaKey is an RSA structure. */
	/* For Openssl 3, rsaKey is an EVP_PKEY, */
	rc = TSS_RSAGeneratePublicTokenI((void **)&rsa_pub_key,	/* freed @3 */
					 narr,      	/* public modulus */
					 nbytes,
					 earr,      	/* public exponent */
					 ebytes);
    }
    /* Must pad first and then encrypt because the encrypt call cannot specify an encoding
       parameter */
    if (rc == 0) {
	padded_data[0] = 0x00;
	rc = TSS_RSA_padding_add_PKCS1_OAEP(padded_data,		    /* to */
					    (uint32_t)encrypt_data_size,    /* to length */
					    decrypt_data,		    /* from */
					    (uint32_t)decrypt_data_size,    /* from length */
					    p,		/* encoding parameter */
					    pl,		/* encoding parameter length */
					    halg);	/* OAEP hash algorithm */
    }
    if (rc == 0) {
        if (tssVverbose)
	    printf("  TSS_RSAPublicEncrypt: Padded data size %lu\n",
		   (unsigned long)encrypt_data_size);
        if (tssVverbose) TSS_PrintAll("  TPM_RSAPublicEncrypt: Padded data", padded_data,
				      (uint32_t)encrypt_data_size);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	/* encrypt with public key. */
	/* returns the size of the encrypted data.  On error, -1 is returned */
	irc = RSA_public_encrypt((int)encrypt_data_size,         /* from length */
				 padded_data,               /* from - the clear text data */
				 encrypt_data,              /* the padded and encrypted data */
				 rsa_pub_key,               /* RSA key structure */
				 RSA_NO_PADDING);           /* padding */
	if (irc < 0) {
	    if (tssVerbose) printf("TSS_RSAPublicEncrypt: Error in RSA_public_encrypt()\n");
	    rc = TSS_RC_RSA_ENCRYPT;
	}
    }
#else
    /* create EVP_PKEY_CTX for the encrypt */
    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new(rsa_pub_key, NULL);		/* freed @1 */
	if (ctx == NULL) {
	    printf("TSS_RSAPublicEncrypt: Error in EVP_PKEY_CTX_new()\n");
            rc = TSS_RC_RSA_ENCRYPT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_encrypt_init(ctx);
	if (irc != 1) {
	    printf("TSS_RSAPublicEncrypt: Error in EVP_PKEY_encrypt_init()\n");
            rc = TSS_RC_RSA_ENCRYPT;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
	if (irc <= 0) {
	    if (tssVerbose) printf("TSS_RSAPublicEncrypt: Error in EVP_PKEY_CTX_set_rsa_padding\n");
	    rc = TSS_RC_RSA_ENCRYPT;
	}
    }
    if (rc == 0) {
	size_t outlen = encrypt_data_size;
	irc = EVP_PKEY_encrypt(ctx,
			       encrypt_data, &outlen,
			       padded_data, encrypt_data_size);
    }
#endif
    if (rc == 0) {
        if (tssVverbose) printf("  TSS_RSAPublicEncrypt: RSA_public_encrypt() success\n");
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
#else
    EVP_PKEY_CTX_free(ctx);		/* @1 */
#endif
   TSS_RsaFree(rsa_pub_key);          	/* @3 */
   free(padded_data);                  	/* @2 */
   return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* TSS_EccFree() frees an openssl ECC key token.

   This abstracts the crypto library specific free.

   For Openssl < 3, eccKey is an EC_KEY structure.
   For Openssl 3, rsaKey is an EVP_PKEY,
*/

void TSS_EccFree(void *eccKey)
{
    if (eccKey != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	EC_KEY_free(eccKey);
#else
	EVP_PKEY_free(eccKey);
#endif
    }
    return;
}

/* TSS_GeneratePlatformEphemeralKey sets the EC parameters to curveID and generates the ephemeral
   key.  It returns the private key and public points.
*/

static TPM_RC TSS_ECC_GeneratePlatformEphemeralKey(BIGNUM 	**ephPrivKey,	/* freed by caller */
						   BIGNUM 	**ephPubX,	/* freed by caller */
						   BIGNUM 	**ephPubY,	/* freed by caller */
						   EC_GROUP 	*ecGroup,
						   int 		curveID)	/* nid */
{
    TPM_RC      	rc = 0;
    int			irc = 0;
    EVP_PKEY_CTX 	*ctx = NULL;
    EVP_PKEY 		*ephKey = NULL;		/* ephemeral key */

    /* create the key generator context */
    if (rc == 0) {
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);	/* freed @1 */
	if (ctx == NULL) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_CTX_new_id()\n");
            rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* initialize the public key algorithm context for a key generation operation */
    if (rc == 0) {
	irc = EVP_PKEY_keygen_init(ctx);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_keygen_init()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the key generation curve */
    if (rc == 0) {
	irc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curveID);
	if (irc <= 0) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* generate the ephemeral key */
    if (rc == 0) {
	irc = EVP_PKEY_keygen(ctx, &ephKey);	/* freed @2 */
	if (irc != 1) {
 	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_generate()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    {
	EC_KEY *ephEcKey = NULL;
	const EC_POINT *ephEcPubKey= NULL;
	const BIGNUM *tmpEphPrivKey = NULL;

	/* get the EC_KEY key from the EVP_PKEY */
	if (rc == 0) {
	    ephEcKey = EVP_PKEY_get0_EC_KEY(ephKey);		/* do not free */
	    if (ephEcKey == NULL) {
		if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				       "Error in EVP_PKEY_get0_EC_KEY()\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	/* get the EC_KEY public points */
	if (rc == 0) {
	    ephEcPubKey =  EC_KEY_get0_public_key(ephEcKey);	/* do not free */
	    if (ephEcPubKey == NULL) {
		if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				       "Error in EC_KEY_get0_public_key()\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	/* get the EC_KEY private key */
	if (rc == 0) {
	    tmpEphPrivKey = EC_KEY_get0_private_key(ephEcKey);	/* do not free */
	    if (tmpEphPrivKey == NULL) {
		if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EC_KEY_get0_private_key()\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
	/* duplicate to agree ith openssl 3.x impleentation, whee the caller frees */
	if (rc == 0) {
	    *ephPrivKey = BN_dup(tmpEphPrivKey);	/* freed by caller */
	    if (ephPrivKey == NULL) {
		if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				       "Error in BN_dup()\n");
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    rc = TSS_BN_new(ephPubX);			/* freed by caller */
	}
	if (rc == 0) {
	    rc = TSS_BN_new(ephPubY);			/* freed by caller */
	}
	/* get the public points */
	if (rc == 0) {
	    irc = EC_POINT_get_affine_coordinates(ecGroup, ephEcPubKey, *ephPubX, *ephPubY, NULL);
	    if (irc != 1) {
		if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				       "Error in EC_POINT_get_affine_coordinates()\n");
		rc = TSS_RC_EC_KEY_CONVERT;
	    }
	}
    }
#else	/* OpenSSL 3.x */
    /* get the private key and public points */
    ecGroup = ecGroup;	/* not used for openssl 3.x */
    if (rc == 0) {
	irc = EVP_PKEY_get_bn_param(ephKey, OSSL_PKEY_PARAM_PRIV_KEY,
				    ephPrivKey); 			/* freed by caller */
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_get_bn_param()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}

    }
    if (rc == 0) {
	irc = EVP_PKEY_get_bn_param(ephKey, OSSL_PKEY_PARAM_EC_PUB_X,
				    ephPubX); 				/* freed by caller */
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_get_bn_param()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}

    }
    if (rc == 0) {
	irc = EVP_PKEY_get_bn_param(ephKey, OSSL_PKEY_PARAM_EC_PUB_Y,
				    ephPubY);				/* freed by caller */
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_GeneratePlatformEphemeralKey: "
				   "Error in EVP_PKEY_get_bn_param()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
#endif
    EVP_PKEY_CTX_free(ctx);	/* @1 */
    EVP_PKEY_free(ephKey);	/* @2 */
    return rc;
}

/* TSS_ECC_GetNid() gets the OpenSSL nid corresponding to the TCG algorithm ID curve */

static TPM_RC TSS_ECC_GetNid(int		*nid,
			     unsigned int	*pointBytes,
			     TPMI_ECC_CURVE 	curveID)
{
    TPM_RC 		rc = 0;

    switch (curveID) {
      case TPM_ECC_NIST_P192:
	*nid = NID_X9_62_prime192v1;	/* untested guess */
	*pointBytes = 24;
	break;
      case TPM_ECC_NIST_P224:
	*nid = NID_secp224r1;		/* untested guess */
	*pointBytes = 28;
	break;
      case TPM_ECC_NIST_P256:		/* TCG standard */
	*nid = NID_X9_62_prime256v1;
	*pointBytes = 32;
	break;
      case TPM_ECC_NIST_P384:		/* TCG standard */
	*nid = NID_secp384r1;
	*pointBytes = 48;
	break;
      case TPM_ECC_NIST_P521:
	*nid = NID_secp521r1;		/* untested guess */
	*pointBytes = 66;
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
	*pointBytes = 0;
	if (tssVerbose) printf("TSS_ECC_GetNid: TCG curve %04x not supported \n", curveID);
	rc = TSS_RC_EC_KEY_CONVERT;
    }
    return rc;
}

/* converts the TPMT_PUBLIC to an OpenSSL public EC_POINT.

   ecGroup is input here, calculated from the nid for the publicArea->parameters.eccDetail.curveID
*/

static TPM_RC TSS_ECC_TPMTPublicToEcPoint(EC_GROUP *ecGroup,
					  TPMT_PUBLIC *publicArea,
					  EC_POINT **tpmPubPoint)	/* freed by caller */
{
    TPM_RC 	rc = 0;
    int 	irc;
    BIGNUM 	*x = NULL;
    BIGNUM 	*y = NULL;

    /* Create the bignums for the coordinates of the point */
    if (rc == 0) {
	rc = TSS_bin2bn(&x,					/* freed @1 */
			publicArea->unique.ecc.x.t.buffer,
			publicArea->unique.ecc.x.t.size);
    }
    if (rc == 0) {
	rc = TSS_bin2bn(&y,					/* freed @2 */
			publicArea->unique.ecc.y.t.buffer,
			publicArea->unique.ecc.y.t.size);
    }
    /* assign curve to EC_POINT */
    if (rc == 0) {
	*tpmPubPoint = EC_POINT_new(ecGroup);			/* freed by caller */
	if (*tpmPubPoint == NULL) {
	    if (tssVerbose) printf("TSS_ECC_TPMTPublicToEcPoint: EC_POINT_new failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* add the public points X and Y */
    if (rc == 0) {
	irc = EC_POINT_set_affine_coordinates(ecGroup, *tpmPubPoint, x, y, NULL);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_TPMTPublicToEcPoint: "
				   "Error calling EC_POINT_set_affine_coordinates()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* sanity check on TPM key, validate that the public point is on the curve */
    if (rc == 0) {
	irc = EC_POINT_is_on_curve(ecGroup, *tpmPubPoint, NULL);
	if (irc != 1) {
	    printf("TSS_ECC_TPMTPublicToEcPoint: EC_POINT_is_on_curve() failed\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    BN_free(x);		/* @1 */
    BN_free(y);		/* @2 */
    return rc;
}

/* TSS_ECC_Salt() returns both the plaintext and excrypted salt, based on the salt key bPublic.

   TPM2B_DIGEST salt - used to caculate the session key
   TPM2B_ENCRYPTED_SECRET - encrypted salt, send to TPM
*/

TPM_RC TSS_ECC_Salt(TPM2B_DIGEST 		*salt,
		    TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
		    TPMT_PUBLIC			*publicArea)		/* salt asymmetric key */
{
    TPM_RC		rc = 0;
    int			irc = 0;
    int			nid = NID_undef;	/* nid for public key */
    unsigned int	pointBytes = 0;		/* bytes in the salt public point */
    BIGNUM 		*ephPrivKey = NULL;	/* ephemeral private key */
    BIGNUM 		*ephPubX = NULL;	/* ephemeral public key X */
    BIGNUM 		*ephPubY = NULL;	/* ephemeral public key Y */
    TPMS_ECC_POINT 	Qeu;			/* ephemeral public point TPM format */
    EC_GROUP 		*ecGroup = NULL;	/* Group defines the used curve */
    EC_POINT 		*tpmPubPoint = NULL;    /* Public part of TPM key */
    EC_POINT 		*pointP = NULL;		/* P = ephemeral private * tpm public */
    BIGNUM 		*ZeeX = NULL;		/* Z = x coordinate of P */
    TPM2B_ECC_PARAMETER Zee;			/* Z = X point of pointP */
    uint32_t		sizeInBytes;		/* digest size based on nameAlg */
    uint32_t		sizeInBits;		/* digest size based on nameAlg */

    /* map from the TPM curve ID to OpenSSL nid, and get the bytes in the point */
    if (rc == 0) {
	rc = TSS_ECC_GetNid(&nid, &pointBytes,
			    publicArea->parameters.eccDetail.curveID);
    }
    /* ecGroup defines the used curve */
    if (rc == 0) {
	if (!(ecGroup = EC_GROUP_new_by_curve_name(nid))) {
	    if (tssVerbose) printf("TSS_ECC_Salt: "
				    "Error calling EC_GROUP_new_by_curve_name()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* Generate the TSS ECC ephemeral key pair outside the TPM for the salt. The public part of this
       key becomes the encrypted salt. */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Calling TSS_ECC_GeneratePlatformEphemeralKey()\n");
	rc = TSS_ECC_GeneratePlatformEphemeralKey(&ephPrivKey,	/* freed @3 */
						  &ephPubX,	/* freed @4 */
						  &ephPubY,	/* freed @5 */
						  ecGroup,
						  nid);
    }
    /* Convert the ephemeral key public point to TPM format. Qeu Part 1 ECDH  */
    if (rc == 0) {
	Qeu.x.t.size = pointBytes;
	rc = TSS_bn2binpad((unsigned char *)&Qeu.x.t.buffer, pointBytes, ephPubX);
    }
    if (rc == 0) {
	Qeu.y.t.size = pointBytes;
	rc = TSS_bn2binpad((unsigned char *)&Qeu.y.t.buffer, pointBytes, ephPubY);
    }
    /* convert the TPM salt public key point to an OpenSSL public point */
    if (rc == 0) {
	rc = TSS_ECC_TPMTPublicToEcPoint(ecGroup, publicArea,
					 &tpmPubPoint);			/* freed @6 */
    }
    /* create an EC_POINT for the multiplication, assign curve from group */
    if (rc == 0) {
	pointP = EC_POINT_new(ecGroup);
	if (pointP == NULL) {
	    if (tssVerbose) printf("TSS_ECC_Salt: EC_POINT_new for pointP failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* Multiply the TPM public key (q) with the ephemeral private key (m)  n + q * m
       See Part 1 C.6.1.	ECDH to calculate the point P */
    if (rc == 0) {
	irc = EC_POINT_mul(ecGroup,
			   pointP,	/* r */
			   NULL,	/* n not used */
			   tpmPubPoint,	/* q */
			   ephPrivKey,	/* m */
			   NULL);	/* ctx */
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_Salt: EC_POINT_mul failed\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* Z is the x-coordinate of P */
    if (rc == 0) {
	rc = TSS_BN_new(&ZeeX);		/* freed @7 */
    }
    if (rc == 0) {
	irc = EC_POINT_get_affine_coordinates(ecGroup, pointP,
					      ZeeX, NULL, NULL);
	if (irc != 1) {
	    if (tssVerbose) printf("TSS_ECC_Salt: EC_POINT_get_affine_coordinates failed\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* convert Z to TPM2B_ECC_PARAMETER */
    if (rc == 0) {
	Zee.t.size = pointBytes;
	rc = TSS_bn2binpad(Zee.t.buffer, pointBytes, ZeeX);
    }
    /* encrypted salt is the ephemeral public key */
    /* Write the public ephemeral key Qeu in TPM format to encryptedSalt output */
    if (rc == 0) {
	BYTE *buffer = encryptedSalt->t.secret;		/* tmp buffer because marshal moves it */
	uint32_t size = sizeof(TPMU_ENCRYPTED_SECRET);	/* max size */
	encryptedSalt->t.size = 0;			/* bytes written aftre marshaling */

	rc = TSS_TPMS_ECC_POINT_Marshalu(&Qeu, &encryptedSalt->t.size, &buffer, &size);
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(publicArea->nameAlg);
	sizeInBits =  sizeInBytes * 8;
	if (tssVverbose) printf("TSS_ECC_Salt: "
				"Calling TSS_KDFE\n");
	/* TPM2B_DIGEST salt size is the largest supported digest algorithm.
	   This has already been validated when unmarshaling the Name hash algorithm.
	*/
	/* salt = KDFe(tpmKey_NameAlg, sharedX, "SECRET", P_caller, P_tpm,
	   tpmKey_NameAlgSizeBits) */
	salt->t.size = sizeInBytes;
	rc = TSS_KDFE((uint8_t *)&salt->t.buffer, 	/* KDFe output */
		      publicArea->nameAlg,		/* hash algorithm */
		      &Zee.b,				/* Z - X point of pointP */
		      "SECRET",				/* KDFe label */
		      &Qeu.x.b,				/* context U - ephemeral public point X */
		      &publicArea->unique.ecc.x.b,	/* context V - X point of TPM key */
		      sizeInBits);			/* required size of key in bits */
    }
    if (rc == 0) { 
	if (tssVverbose) TSS_PrintAll("TSS_ECC_Salt: salt",
				      (uint8_t *)&salt->t.buffer,
				      salt->t.size);
    }
    EC_GROUP_free(ecGroup);		/* @1 */
    BN_clear_free(ephPrivKey);		/* @3 */
    BN_free(ephPubX);			/* @4 */
    BN_free(ephPubY);			/* @5 */
    EC_POINT_free(tpmPubPoint);		/* @6 */
    BN_clear_free(ZeeX);		/* @7 */
    return rc;
}

/* TSS_BN_new() wraps the openSSL function in a TPM error handler
 */

static TPM_RC TSS_BN_new(BIGNUM **bn)		/* freed by caller */
{
    TPM_RC	rc = 0;

    if (rc == 0) {
	if (*bn != NULL) {
	    if (tssVerbose)
		printf("TSS_BN_new: Error (fatal), *bn %p should be NULL before BN_new()\n", *bn);
	    rc = TSS_RC_ALLOC_INPUT;
	}
    }
    if (rc == 0) {
	*bn = BN_new();
	if (*bn == NULL) {
	    if (tssVerbose) printf("TSS_BN_new: BN_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* TSS_bin2bn() wraps the openSSL function in a TPM error handler

   Converts a char array to bignum

   bn must be freed by the caller.
*/

static TPM_RC TSS_bin2bn(BIGNUM **bn, const unsigned char *bin, unsigned int bytes)
{
    TPM_RC	rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            if (tssVerbose) printf("TSS_bin2bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

#ifndef TPM_TSS_NOECC

/* TSS_bn2binpad() wraps the openSSL function in a TPM error handler

   Converts a bignum to padded char array
*/

static TPM_RC TSS_bn2binpad(unsigned char *bin, int binlen, const BIGNUM *bn)
{
    TPM_RC	rc = 0;
    int		irc = 0;

    irc = BN_bn2binpad(bn, bin, binlen);
    if (irc == -1) {
	if (tssVerbose) printf("TSS_bn2binpad: Error in BN_bn2binpad\n");
	rc = TSS_RC_BIGNUM;
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/*
  AES
*/

#if OPENSSL_VERSION_NUMBER < 0x30000000
TPM_RC TSS_AES_GetEncKeySize(size_t *tssSessionEncKeySize)
{
    *tssSessionEncKeySize = sizeof(AES_KEY);
    return 0;
}
TPM_RC TSS_AES_GetDecKeySize(size_t *tssSessionDecKeySize)
{
    *tssSessionDecKeySize = sizeof(AES_KEY);
    return 0;
}
#endif

/* TSS_AES_KeyAllocate() allocates memory for the AES encryption and decryption keys.
 */

TPM_RC TSS_AES_KeyAllocate(void **tssSessionEncKey,
			   void **tssSessionDecKey)
{
    TPM_RC		rc = 0;

#if OPENSSL_VERSION_NUMBER < 0x30000000
    size_t tssSessionEncKeySize;
    size_t tssSessionDecKeySize;

    /* crypto library dependent code to allocate the session state encryption and decryption keys.
       They are probably always the same size, but it's safer not to assume that. */
    if (rc == 0) {
	rc = TSS_AES_GetEncKeySize(&tssSessionEncKeySize);
    }
    if (rc == 0) {
	rc = TSS_AES_GetDecKeySize(&tssSessionDecKeySize);
    }
    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)tssSessionEncKey, (uint32_t)tssSessionEncKeySize);
    }
    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)tssSessionDecKey, (uint32_t)tssSessionDecKeySize);
    }
#else
    if (rc == 0) {
	*tssSessionEncKey = EVP_CIPHER_CTX_new();
	if (*tssSessionEncKey == NULL) {
	    if (tssVerbose)
		printf("TSS_AES_KeyAllocate: Error creating openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    if (rc == 0) {
	*tssSessionDecKey = EVP_CIPHER_CTX_new();
	if (*tssSessionDecKey == NULL) {
	    if (tssVerbose)
		printf("TSS_AES_KeyAllocate: Error creating openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
#endif
    return rc;
}

TPM_RC TSS_AES_KeyFree(void *tssSessionEncKey,
		       void *tssSessionDecKey)
{
    TPM_RC rc = 0;

#ifndef TPM_TSS_NOFILE
#if OPENSSL_VERSION_NUMBER < 0x30000000
    free(tssSessionEncKey);
    free(tssSessionDecKey);
#else
    EVP_CIPHER_CTX_free(tssSessionEncKey);
    EVP_CIPHER_CTX_free(tssSessionDecKey);
#endif	/* OPENSSL_VERSION_NUMBER  */
#else
    tssSessionEncKey = tssSessionEncKey;
    tssSessionDecKey = tssSessionDecKey;
#endif	/* TPM_TSS_NOFILE */
    return rc;
}

#define TSS_AES_KEY_BITS 128

#ifndef TPM_TSS_NOFILE

TPM_RC TSS_AES_KeyGenerate(void *tssSessionEncKey,
			   void *tssSessionDecKey)
{
    TPM_RC		rc = 0;
    int 		irc;
    unsigned char 	userKey[AES_128_BLOCK_SIZE_BYTES];
    const char 		*envKeyString = NULL;
    unsigned char 	*envKeyBin = NULL;
    size_t 		envKeyBinLen;

    if (rc == 0) {
	envKeyString = getenv("TPM_SESSION_ENCKEY");
    }
    if (envKeyString == NULL) {
	/* If the env variable TPM_SESSION_ENCKEY is not set, generate a random key for this
	   TSS_CONTEXT */
	if (rc == 0) {
	    /* initialize userKey to silence valgrind false positive */
	    memset(userKey, 0, sizeof(userKey));
	    rc = TSS_RandBytes(userKey, AES_128_BLOCK_SIZE_BYTES);
	}
    }
    /* The env variable TPM_SESSION_ENCKEY can set a (typically constant) encryption key.  This is
       useful for scripting, where the env variable is set to a random seed at the beginning of the
       script. */
    else {
	/* hexascii to binary */
	if (rc == 0) {
	    rc = TSS_Array_Scan(&envKeyBin,			/* freed @1 */
				&envKeyBinLen, envKeyString);
	}
	/* range check */
	if (rc == 0) {
	    if (envKeyBinLen != AES_128_BLOCK_SIZE_BYTES) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error, env variable length %lu not %lu\n",
			   (unsigned long)envKeyBinLen, (unsigned long)sizeof(userKey));
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
	/* copy the binary to the common userKey for use below */
	if (rc == 0) {
	    memcpy(userKey, envKeyBin, envKeyBinLen);
	}
    }
    /* translate userKey to openssl key tokens */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
        irc = AES_set_encrypt_key(userKey,
                                  TSS_AES_KEY_BITS,
                                  tssSessionEncKey);
	/* should never occur, null pointers or bad bit size */
	if (irc != 0) {
            if (tssVerbose)
		printf("TSS_AES_KeyGenerate: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    if (rc == 0) {
	irc = AES_set_decrypt_key(userKey,
				  TSS_AES_KEY_BITS,
				  tssSessionDecKey);
	/* should never occur, null pointers or bad bit size */
	if (irc != 0) {
            if (tssVerbose)
		printf("TSS_AES_KeyGenerate: Error setting openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
#else
    {
	EVP_CIPHER *cipher = NULL;
	unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */
        memset(ivec, 0, sizeof(ivec));

	if (rc == 0) {
	    cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);	/* freed @1 */
	    if (cipher == NULL) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error getting openssl cipher\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
	    }
	}
	/* encryption context */
	if (rc == 0) {
	    irc = EVP_CipherInit_ex2(tssSessionEncKey, cipher, userKey, ivec, 1, NULL);
	    if (irc != 1) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error setting openssl AES encryption key\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
	    }
	}
	if (rc == 0) {		/* always returns 1 */
	    EVP_CIPHER_CTX_set_padding(tssSessionEncKey, 0);
	}
	/* decryption context */
	if (rc == 0) {
	    irc = EVP_CipherInit_ex2(tssSessionDecKey, cipher, userKey, ivec, 0, NULL);
	    if (irc != 1) {
		if (tssVerbose)
		    printf("TSS_AES_KeyGenerate: Error setting openssl AES decryption key\n");
		rc = TSS_RC_AES_KEYGEN_FAILURE;
	    }
	}
	if (rc == 0) {		/* always returns 1 */
	    EVP_CIPHER_CTX_set_padding(tssSessionDecKey, 0);
	}
	EVP_CIPHER_free(cipher);	/* @1 */

    }
#endif
    free(envKeyBin);	/* @1 */
    return rc;
}

#endif

/* TSS_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to 'encrypt_data' using CBC.
   This function uses the session encryption key for encrypting session state.

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

TPM_RC TSS_AES_Encrypt(void *tssSessionEncKey,
		       unsigned char **encrypt_data,   		/* output, caller frees */
		       uint32_t *encrypt_length,		/* output */
		       const unsigned char *decrypt_data,	/* input */
		       uint32_t decrypt_length)			/* input */
{
    TPM_RC		rc = 0;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    int 		irc;
#endif
    uint32_t		pad_length;
    unsigned char	*decrypt_data_pad = NULL;

    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = AES_128_BLOCK_SIZE_BYTES - (decrypt_length % AES_128_BLOCK_SIZE_BYTES);
        *encrypt_length = decrypt_length + pad_length;
         /* allocate memory for the encrypted response */
        rc = TSS_Malloc(encrypt_data, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(&decrypt_data_pad, *encrypt_length);    /* freed @1 */
    }
    /* pad the decrypted clear text data */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
        /* last gets pad = pad length */
        memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
        /* set the IV */
	unsigned char	ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */
        memset(ivec, 0, sizeof(ivec));
        /* encrypt the padded input to the output */
        AES_cbc_encrypt(decrypt_data_pad,
                        *encrypt_data,
                        *encrypt_length,
                        tssSessionEncKey,
                        ivec,
                        AES_ENCRYPT);
    }
#else
    /* reset the encrypt context */
    if (rc == 0) {
	irc = EVP_CipherInit_ex2(tssSessionEncKey, NULL, NULL, NULL, 1, NULL);
	if (irc != 1) {
	    if (tssVerbose)
		printf("TSS_AES_Encrypt: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }
    if (rc == 0) {
	uint32_t decrypt_length_pad = decrypt_length + pad_length;
	int encLength;		/* because openssl uses an int length */
	irc = EVP_CipherUpdate(tssSessionEncKey,
			       *encrypt_data, &encLength,
				decrypt_data_pad, decrypt_length_pad);
	*encrypt_length = encLength;	/* cast back to unsigned for return */
	if (irc != 1) {
	    if (tssVerbose)
		printf("TSS_AES_Encrypt: Error in EVP_EncryptUpdate\n");
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }
#endif
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

/* TSS_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to 'decrypt_data' using CBC.
   This function uses the session encryption key for decrypting session state.

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

TPM_RC TSS_AES_Decrypt(void *tssSessionDecKey,
		       unsigned char **decrypt_data,   		/* output, caller frees */
		       uint32_t *decrypt_length,		/* output */
		       const unsigned char *encrypt_data,	/* input */
		       uint32_t encrypt_length)			/* input */
{
    TPM_RC          	rc = 0;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    int 		irc;
#endif
    uint32_t		pad_length;
    uint32_t		i;
    unsigned char       *pad_data;

    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < AES_128_BLOCK_SIZE_BYTES) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad length %u\n",
				   encrypt_length);
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TSS_Malloc(decrypt_data, encrypt_length);
    }
    /* decrypt the input to the padded output */
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (rc == 0) {
	/* set the IV */
	unsigned char       ivec[AES_128_BLOCK_SIZE_BYTES];       /* initial chaining vector */
        memset(ivec, 0, sizeof(ivec));
        /* decrypt the padded input to the output */
        AES_cbc_encrypt(encrypt_data,
                        *decrypt_data,
                        encrypt_length,
                        tssSessionDecKey,
                        ivec,
                        AES_DECRYPT);
    }
#else
    /* reset the decrypt context */
    if (rc == 0) {
	irc = EVP_CipherInit_ex2(tssSessionDecKey, NULL, NULL, NULL, 0, NULL);
	if (irc != 1) {
	    if (tssVerbose)
		printf("TSS_AES_Decrypt: Error setting openssl AES decryption key\n");
	    rc = TSS_RC_AES_DECRYPT_FAILURE;
	}
    }
    if (rc == 0) {
	int decLength;		/* because openssl uses an int length */
	irc = EVP_DecryptUpdate(tssSessionDecKey,
				*decrypt_data, &decLength,
				encrypt_data, encrypt_length);
	*decrypt_length = decLength;	/* cast back to unsigned for return */
	if (irc != 1) {
	    if (tssVerbose)
		printf("TSS_AES_Decrypt: Error in EVP_DecryptUpdate\n");
	    rc = TSS_RC_AES_DECRYPT_FAILURE;
	}
    }
#endif
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        if ((pad_length == 0) ||
            (pad_length > AES_128_BLOCK_SIZE_BYTES)) {
            if (tssVerbose) printf("TSS_AES_Decrypt: Error, illegal pad length\n");
            rc = TSS_RC_AES_DECRYPT_FAILURE;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; (rc == 0) && (i < pad_length) ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                if (tssVerbose) printf("TSS_AES_Decrypt: Error, bad pad %02x at index %u\n",
				       *pad_data, i);
                rc = TSS_RC_AES_DECRYPT_FAILURE;
            }
        }
    }
    return rc;
}

TPM_RC TSS_AES_EncryptCFB(uint8_t	*dOut,		/* OUT: the encrypted data */
			  uint32_t	keySizeInBits,	/* IN: key size in bits */
			  uint8_t 	*key,           /* IN: key buffer */
			  uint8_t 	*iv,		/* IN/OUT: IV for decryption */
			  uint32_t	dInSize,       	/* IN: data size */
			  uint8_t 	*dIn)		/* IN: data buffer */
{
    TPM_RC	rc = 0;
    int 	irc;

#if OPENSSL_VERSION_NUMBER < 0x30000000
    int		blockSize;
    int32_t	dSize;         /* signed version of dInSize */
    AES_KEY	aeskey;

    /* Create AES encryption key token */
    if (rc == 0) {
	memset(&aeskey, 0, sizeof(AES_KEY));	/* to suppress Coverity false positive */
	irc = AES_set_encrypt_key(key, keySizeInBits, &aeskey);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_EncryptCFB: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;  /* should never occur, null pointers or bad bit size */
	}
    }
    if (rc == 0) {
	/* Encrypt the current IV into the new IV, XOR in the data, and copy to output */
	for(dSize = (int32_t)dInSize ; dSize > 0 ; dSize -= 16, dOut += 16, dIn += 16) {
	    /* Encrypt the current value of the IV to the intermediate value.  Store in old iv,
	       since it's not needed anymore. */
	    AES_encrypt(iv, iv, &aeskey);
	    blockSize = (dSize < 16) ? dSize : 16;	/* last block can be < 16 */
	    TSS_XOR(dOut, dIn, iv, blockSize);
	    memcpy(iv, dOut, blockSize);
	}
    }
#else
    {
	EVP_CIPHER_CTX *ctx = NULL;

	/* initialize the key context */
	if (rc == 0) {
	    rc = TSS_AES_CFB(&ctx,		/* freed @2 */
			     keySizeInBits,	/* IN: key size in bits */
			     key,           	/* IN: key buffer */
			     iv,            	/* IN: IV */
			     1);		/* encrypt */
	}
	if (rc == 0) {
	    int encLength;		/* because openssl uses an int length */
	    irc = EVP_CipherUpdate(ctx,
				   dOut, &encLength,
				   dIn, dInSize);
	    if (irc != 1) {
		if (tssVerbose)
		    printf("TSS_AES_EncryptCFB: Error in EVP_EncryptUpdate\n");
		rc = TSS_RC_AES_ENCRYPT_FAILURE;
	    }
	}
	EVP_CIPHER_CTX_free(ctx);	/* @2 */
    }
#endif
    return rc;
}

TPM_RC TSS_AES_DecryptCFB(uint8_t *dOut,          	/* OUT: the decrypted data */
			  uint32_t keySizeInBits, 	/* IN: key size in bits */
			  uint8_t *key,           	/* IN: key buffer */
			  uint8_t *iv,            	/* IN/OUT: IV for decryption. */
			  uint32_t dInSize,       	/* IN: data size */
			  uint8_t *dIn)			/* IN: data buffer */
{
    TPM_RC	rc = 0;
    int 	irc;

#if OPENSSL_VERSION_NUMBER < 0x30000000
    uint8_t	tmp[16];
    int		blockSize;
    AES_KEY	aesKey;
    int32_t	dSize;

    /* Create AES encryption key token */
    if (rc == 0) {
	memset(&aesKey, 0, sizeof(AES_KEY));	/* to suppress Coverity false positive */
	irc = AES_set_encrypt_key(key, keySizeInBits, &aesKey);
	if (irc != 0) {
            if (tssVerbose) printf("TSS_AES_DecryptCFB: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;  /* should never occur, null pointers or bad bit size */
	}
    }
    if (rc == 0) {
	for (dSize = (int32_t)dInSize ; dSize > 0; dSize -= 16, dOut += 16, dIn += 16) {
	    /* Encrypt the IV into the temp buffer */
	    AES_encrypt(iv, tmp, &aesKey);
	    blockSize = (dSize < 16) ? dSize : 16;	/* last block can be < 16 */
	    TSS_XOR(dOut, dIn, tmp, blockSize);
	    memcpy(iv, dIn, blockSize);
	}
    }
#else
    {
	EVP_CIPHER_CTX *ctx = NULL;

	/* initialize the key context */
	if (rc == 0) {
	    rc = TSS_AES_CFB(&ctx,		/* freed @2 */
			     keySizeInBits,	/* IN: key size in bits */
			     key,           	/* IN: key buffer */
			     iv,            	/* IN: IV */
			     0);		/* encrypt */
	}
	if (rc == 0) {
	    int encLength;		/* because openssl uses an int length */
	    irc = EVP_CipherUpdate(ctx,
				   dOut, &encLength,
				   dIn, dInSize);
	    if (irc != 1) {
		if (tssVerbose)
		    printf("TSS_AES_DecryptCFB: Error in EVP_EncryptUpdate\n");
		rc = TSS_RC_AES_DECRYPT_FAILURE;
	    }
	}
	EVP_CIPHER_CTX_free(ctx);	/* @2 */
    }
#endif
   return rc;
}

#if OPENSSL_VERSION_NUMBER >=  0x30000000
/* TSS_AES_CFB() is openssl common code to initialize the key context for AES CFB encrypt and
   decrypt */

static TPM_RC TSS_AES_CFB(EVP_CIPHER_CTX **ctx,		/* freed by caller */
			  uint32_t keySizeInBits,	/* IN: key size in bits */
			  uint8_t *key,           	/* IN: key buffer */
			  uint8_t *iv,            	/* IN: IV */
			  int encrypt)			/* boolean */

{
    TPM_RC	rc = 0;
    int 	irc;
    EVP_CIPHER *cipher = NULL;

    /* currently supports CFB AES 128 and 256 */
    if (rc == 0) {
	switch (keySizeInBits) {
	  case 128:
	    cipher = EVP_CIPHER_fetch(NULL, "AES-128-CFB", NULL);	/* freed @1 */
	    break;
	  case 256:
	    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CFB", NULL);	/* freed @1 */
	    break;
	  default:
	    printf("TSS_AES_CFB: keySizeInBits %u not supported\n", keySizeInBits);
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	    break;
	}
	if (cipher == NULL) {
	    if (tssVerbose)
		printf("TSS_AES_CFB: Error getting openssl cipher\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    /* allocate the context */
    if (rc == 0) {
	*ctx = EVP_CIPHER_CTX_new();		/* freed by caller */
	if (ctx == NULL) {
	    if (tssVerbose)
		printf("TSS_AES_CFB: Error creating openssl AES decryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    /* initialize the context with the key and IV */
    if (rc == 0) {
	irc = EVP_CipherInit_ex2(*ctx, cipher, key, iv, encrypt, NULL);
	if (irc != 1) {
	    if (tssVerbose)
		printf("TSS_AES_CFB: Error setting openssl AES encryption key\n");
	    rc = TSS_RC_AES_KEYGEN_FAILURE;
	}
    }
    EVP_CIPHER_free(cipher);	/* @1 */
    return rc;
}
#endif
