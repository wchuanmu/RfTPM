/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TestingCommands.c 1490 2019-07-26 21:13:22Z kgoldman $	*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2021				*/
/*										*/
/********************************************************************************/

#include "Tpm.h"
#include "SelfTest_fp.h"

extern int verbose;

#if CC_SelfTest  // Conditional expansion of this file
TPM_RC
TPM2_SelfTest(
	      SelfTest_In     *in             // IN: input parameter list
	      )
{
  //   if (verbose) {
	// FILE *f = fopen("trace.txt", "a");
	// fprintf(f, "TPM2_SelfTest:\n");
	// fclose(f);
  //   }
    // Command Output
    // Call self test function in crypt module
    return CryptSelfTest(in->fullTest);
}
#endif // CC_SelfTest
#include "Tpm.h"
#include "IncrementalSelfTest_fp.h"
#if CC_IncrementalSelfTest  // Conditional expansion of this file
TPM_RC
TPM2_IncrementalSelfTest(
			 IncrementalSelfTest_In      *in,            // IN: input parameter list
			 IncrementalSelfTest_Out     *out            // OUT: output parameter list
			 )
{
    TPM_RC                       result;
  //   if (verbose) {
	// FILE *f = fopen("trace.txt", "a");
	// fprintf(f, "TPM2_IncrementalSelfTest:\n");
	// fclose(f);
  //   }
    // Command Output
    // Call incremental self test function in crypt module. If this function
    // returns TPM_RC_VALUE, it means that an algorithm on the 'toTest' list is
    // not implemented.
    result = CryptIncrementalSelfTest(&in->toTest, &out->toDoList);
    if(result == TPM_RC_VALUE)
	return TPM_RCS_VALUE + RC_IncrementalSelfTest_toTest;
    return result;
}
#endif // CC_IncrementalSelfTest
#include "Tpm.h"
#include "GetTestResult_fp.h"
#if CC_GetTestResult  // Conditional expansion of this file
TPM_RC
TPM2_GetTestResult(
		   GetTestResult_Out   *out            // OUT: output parameter list
		   )
{
  //   if (verbose) {
	// FILE *f = fopen("trace.txt", "a");
	// fprintf(f, "TPM2_GetTestResult:\n");
	// fclose(f);
  //   }
    // Command Output
    // Call incremental self test function in crypt module
    out->testResult = CryptGetTestResult(&out->outData);
    return TPM_RC_SUCCESS;
}
#endif // CC_GetTestResult
