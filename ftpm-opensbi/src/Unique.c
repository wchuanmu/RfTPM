/********************************************************************************/
/*										*/
/*			  Secret Value to the TPM   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2023				*/
/*										*/
/********************************************************************************/

//** Introduction
// In some implementations of the TPM, the hardware can provide a secret
// value to the TPM. This secret value is statistically unique to the
// instance of the TPM. Typical uses of this value are to provide
// personalization to the random number generation and as a shared secret
// between the TPM and the manufacturer.

//** Includes
#include "Platform.h"

#if VENDOR_PERMANENT_AUTH_ENABLED == YES

const char notReallyUnique[] = "This is not really a unique value. A real "
			       "unique value should"
			       " be generated by the platform.";

//** _plat__GetUnique()
// This function is used to access the platform-specific vendor unique values.
// This function places the unique value in the provided buffer ('b')
// and returns the number of bytes transferred. The function will not
// copy more data than 'bSize'.
// NOTE: If a platform unique value has unequal distribution of uniqueness
// and 'bSize' is smaller than the size of the unique value, the 'bSize'
// portion with the most uniqueness should be returned.
//
// 'which' indicates the unique value to return:
// 0 = RESERVED, do not use
// 1 = the VENDOR_PERMANENT_AUTH_HANDLE authorization value for this device
LIB_EXPORT uint32_t _plat__GetUnique(uint32_t which,  // which vendor value to return?
				     uint32_t bSize,  // size of the buffer
				     unsigned char* b  // output buffer
				     )
{
    const char* from   = notReallyUnique;
    uint32_t    retVal = 0;

    if(which == 1)
	{
	    const size_t uSize =
		sizeof(notReallyUnique) <= bSize ? sizeof(notReallyUnique) : bSize;
	    MemoryCopy(b, notReallyUnique, uSize);
	}
    // else fall through to default 0

    return retVal;
}

#endif