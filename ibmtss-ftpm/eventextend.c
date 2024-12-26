/********************************************************************************/
/*										*/
/*		      Extend an EVENT measurement file into PCRs		*/
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

/* eventextend is test/demo code.  It parses a TPM2 event log file and extends the measurements into
   TPM PCRs or simulated PCRs.  This simulates the actions that would be performed by BIOS / UEFI /
   pre-OS firmware in a hardware platform.

   It can optionally:

   - check the calculated, simulated PCR against the TPM PCRs
   - check the digest against the event log data

   It handles the EV_NO_ACTION StartupLocality by power cycling the TPM and sending a startup
   at the locality from the event.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsstransmit.h>	/* for simulator power up */

#include "eventlib.h"

/* local prototypes */

static uint32_t powerUp(void);
static uint32_t startup(TSS_CONTEXT	*tssContext,
			uint8_t 	locality);
static uint32_t pcrExtend(TSS_CONTEXT		*tssContext,
			  TCG_PCR_EVENT2 	*event2);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int 			i = 0;
    TSS_CONTEXT			*tssContext = NULL;
    const char 			*infilename = NULL;
    FILE 			*infile = NULL;
    int				tpm = FALSE;	/* extend into TPM */
    int				sim = FALSE;	/* extend into simulated PCRs */
    int				checkHash = FALSE;	/* verify event log hashes */
    int				checkPcr = FALSE;	/* verify PCRs */
    int				nospec = FALSE;	/* event log does not start with spec file */
    int				noSpace = FALSE;
    uint32_t 			bankNum = 0;	/* PCR hash bank */
    unsigned int 		pcrNum = 0;	/* PCR number iterator */
    TPMI_DH_PCR 		pcrMax = 7;
    TPMT_HA 			simPcrs[HASH_COUNT][IMPLEMENTATION_PCR];
    TPMT_HA 			bootAggregates[HASH_COUNT];
    TCG_PCR_EVENT2 		event2;			/* TPM 2.0 event log entry */
    TCG_PCR_EVENT 		event;			/* TPM 1.2 event log entry */
    TCG_EfiSpecIDEvent 		specIdEvent;
    unsigned int 		lineNum;
    int 			endOfFile = FALSE;
	
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
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
	else if (strcmp(argv[i],"-tpm") == 0) {
	    tpm = TRUE;
	}
	else if (strcmp(argv[i],"-nospec") == 0) {
	    nospec = TRUE;
	}
	else if (strcmp(argv[i],"-sim") == 0) {
	    sim = TRUE;
	}
	else if (strcmp(argv[i],"-checkhash") == 0) {
	    checkHash = TRUE;
	}
	else if (strcmp(argv[i],"-checkpcr") == 0) {
	    checkPcr = TRUE;
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
	}
	else if (strcmp(argv[i],"-pcrmax") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrMax);
	    }
	    else {
		printf("Missing parameter for -pcrmax");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    tssUtilsVerbose = TRUE;
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
    if (sim && nospec) {
	printf("-sim incompatible with -nospec\n");
	printUsage();
    }
    /*
    ** read the event log file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /* the first event is a TPM 1.2 format event */
    /* read an event line */
    if ((rc == 0) && !nospec) {
	rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
    }
    /* debug tracing */
    if ((rc == 0) && !nospec && !endOfFile && tssUtilsVerbose) {
	printf("\neventextend: line 0\n");
	TSS_EVENT_Line_Trace(&event);
    }
    /* parse the event, populates the TCG_EfiSpecIDEvent structure */
    if ((rc == 0) && !nospec && !endOfFile) {
	rc = TSS_SpecIdEvent_Unmarshal(&specIdEvent,
				       event.eventDataSize, event.event);
    }
    /* range check numberOfAlgorithms before the trace */
    if ((rc == 0) && !nospec && !endOfFile) {
	if (specIdEvent.numberOfAlgorithms > HASH_COUNT) {
	    printf("specIdEvent.numberOfAlgorithms %u greater than %u\n",
		   specIdEvent.numberOfAlgorithms, HASH_COUNT);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* trace the specIdEvent event */
    if ((rc == 0) && !nospec && !endOfFile && tssUtilsVerbose) {
	TSS_SpecIdEvent_Trace(&specIdEvent);
    }
    /* Start a TSS context for PCR extend and/or PCR read */
    if ((rc == 0) && (tpm || (sim && checkPcr))) {
	rc = TSS_Create(&tssContext);
    }
    /* initialize simulated PCRs */
    if ((rc == 0) && sim) {
	if (specIdEvent.numberOfAlgorithms > HASH_COUNT) {
	    printf("specIdEvent.numberOfAlgorithms %u greater than %u\n",
		   specIdEvent.numberOfAlgorithms, HASH_COUNT);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* simulated PCRs start at zero or ff at boot */
    if ((rc == 0) && sim) {
	for (bankNum = 0 ; bankNum < specIdEvent.numberOfAlgorithms ; bankNum++) {
	    bootAggregates[bankNum].hashAlg = specIdEvent.digestSizes[bankNum].algorithmId;
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		/* initialize each algorithm ID based on the specIdEvent */
		simPcrs[bankNum][pcrNum].hashAlg = specIdEvent.digestSizes[bankNum].algorithmId;
		if ((pcrNum < 17) || (pcrNum > 22)) {
		    memset(&simPcrs[bankNum][pcrNum].digest.tssmax, 0, sizeof(TPMU_HA));
		}
		/* some PC Client PCRs initialize to all ff */
		else {
		    memset(&simPcrs[bankNum][pcrNum].digest.tssmax, 0xff, sizeof(TPMU_HA));
		}
	    }
	}
	/* void the unused banks so they will never match an event */
	for (; bankNum < HASH_COUNT ; bankNum++) {
	    simPcrs[bankNum][0].hashAlg = TPM_ALG_NULL;
	}
    }
    /* scan each measurement 'line' in the binary */
    for (lineNum = 1 ; (rc == 0) && !endOfFile ; lineNum++) {

	/* read a TPM 2.0 hash agile event line */
	if (rc == 0) {
	    rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
	}
	/* debug tracing */
	if ((rc == 0) && !endOfFile && tssUtilsVerbose) {
	    printf("\neventextend: line %u\n", lineNum);
	    TSS_EVENT2_Line_Trace(&event2);
	}
	/* verify the event PCR digest against the event data */
	if ((rc == 0) && !endOfFile && checkHash) {
	    rc = TSS_EVENT2_Line_CheckHash(&event2, &specIdEvent);
	}
	if ((rc == 0) && !endOfFile && tpm) {		/* extend TPM */
	    rc = pcrExtend(tssContext, &event2);
	}
	if ((rc == 0) && !endOfFile && sim && tssUtilsVerbose &&
	    (event2.pcrIndex < IMPLEMENTATION_PCR)) {	/* trace simulated PCRs */
	    for (bankNum = 0 ; bankNum < specIdEvent.numberOfAlgorithms ; bankNum++) {
		TSS_PrintAll("PCR simulated digest before extend",
			     simPcrs[bankNum][event2.pcrIndex].digest.tssmax,
			     specIdEvent.digestSizes[bankNum].digestSize);
	    }
	}
	if ((rc == 0) && !endOfFile && sim) {		/* extend simulated PCRs */
	    rc = TSS_EVENT2_PCR_Extend(simPcrs, &event2);
	}
	if ((rc == 0) && !endOfFile && sim && tssUtilsVerbose &&
	    (event2.pcrIndex < IMPLEMENTATION_PCR)) {	/* trace simulated PCRs */
	    for (bankNum = 0 ; bankNum < specIdEvent.numberOfAlgorithms ; bankNum++) {
		TSS_PrintAll("PCR simulated digest after extend",
			     simPcrs[bankNum][event2.pcrIndex].digest.tssmax,
			     specIdEvent.digestSizes[bankNum].digestSize);
	    }
	}
    }
    if ((rc == 0) && sim) {
	for (bankNum = 0 ; (rc == 0) && (bankNum < specIdEvent.numberOfAlgorithms) ; bankNum++) {
	    /* trace the virtual PCRs */
	    if (rc == 0) {
	        char pcrString[9];	/* PCR number */

		printf("\n");
		TSS_TPM_ALG_ID_Print("algorithmId", specIdEvent.digestSizes[bankNum].algorithmId, 0);
		for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		    sprintf(pcrString, "PCR %02u:", pcrNum);
		    if (!noSpace) {
			/* TSS_PrintAllLogLevel() with a log level of LOGLEVEL_INFO to print the byte
			   array on one line with no length */
			TSS_PrintAllLogLevel(LOGLEVEL_INFO, pcrString, 1,
					     simPcrs[bankNum][pcrNum].digest.tssmax,
					     specIdEvent.digestSizes[bankNum].digestSize);
		    }
		    else {	/* print with no spaces */
			uint32_t bp;
			printf("PCR %02u: ", pcrNum);
			for (bp = 0 ; bp < specIdEvent.digestSizes[bankNum].digestSize ; bp++) {
			    printf("%02x", simPcrs[bankNum][pcrNum].digest.tssmax[bp]);
			}
			printf("\n");
		    }
		}
	    }
	    /* verify the TPM PCRs against the calculated values */
	    if ((rc == 0) && checkPcr) {
		for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		    PCR_Read_In 		in;
		    PCR_Read_Out 		out;
		    /* read the PCR */
		    if (rc == 0) {
			in.pcrSelectionIn.count = 1;
			in.pcrSelectionIn.pcrSelections[0].hash =
			    specIdEvent.digestSizes[bankNum].algorithmId;
			in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
			in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
			in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
			in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
			in.pcrSelectionIn.pcrSelections[0].pcrSelect[pcrNum / 8] = 1 << (pcrNum % 8);
			rc = TSS_Execute(tssContext,
					 (RESPONSE_PARAMETERS *)&out,
					 (COMMAND_PARAMETERS *)&in,
					 NULL,
					 TPM_CC_PCR_Read,
					 TPM_RH_NULL, NULL, 0);
		    }
		    /* compare the PCR to the calculated value */
		    if (rc == 0) {
			if (specIdEvent.digestSizes[bankNum].digestSize !=
			    out.pcrValues.digests[0].t.size) {
			    printf("eventextend: PCR %u digest size TPM %u simulated %u\n",
				   pcrNum,
				   specIdEvent.digestSizes[bankNum].digestSize,
				   out.pcrValues.digests[0].t.size);
			    rc = TSS_RC_BAD_READ_VALUE;
			}
		    }
		    if (rc == 0) {
			int i = memcmp(simPcrs[bankNum][pcrNum].digest.tssmax,
				       out.pcrValues.digests[0].t.buffer,
				       out.pcrValues.digests[0].t.size);
			if (i != 0) {
			    printf("eventextend: PCR %u\n", pcrNum);
			    TSS_PrintAll("PCR TPM digest",
					 out.pcrValues.digests[0].t.buffer,
					 out.pcrValues.digests[0].t.size);
			    TSS_PrintAll("PCR simulated digest",
					 simPcrs[bankNum][pcrNum].digest.tssmax,
					 out.pcrValues.digests[0].t.size);
			    rc = TSS_RC_BAD_READ_VALUE;
			}
		    }
		}
	    }
	    /* calculate the boot aggregate, hash of PCRs, default 0-7 */
	    if (rc == 0) {
		int length[IMPLEMENTATION_PCR];
		size_t j;
		for (j = 0 ; j < IMPLEMENTATION_PCR ; j++) {
		    if (j <= pcrMax) {	/* include PCRs up to here */
			length[j] = specIdEvent.digestSizes[bankNum].digestSize;
		    }
		    else {
			length[j] = 0;	/* exclude PCRs after to here */
		    }
		}
		rc = TSS_Hash_Generate(&bootAggregates[bankNum],
				       length[0], &simPcrs[bankNum][0].digest.tssmax,
				       length[1], &simPcrs[bankNum][1].digest.tssmax,
				       length[2], &simPcrs[bankNum][2].digest.tssmax,
				       length[3], &simPcrs[bankNum][3].digest.tssmax,
				       length[4], &simPcrs[bankNum][4].digest.tssmax,
				       length[5], &simPcrs[bankNum][5].digest.tssmax,
				       length[6], &simPcrs[bankNum][6].digest.tssmax,
				       length[7], &simPcrs[bankNum][7].digest.tssmax,
				       length[8], &simPcrs[bankNum][8].digest.tssmax,
				       length[9], &simPcrs[bankNum][9].digest.tssmax,
				       length[10], &simPcrs[bankNum][10].digest.tssmax,
				       length[11], &simPcrs[bankNum][11].digest.tssmax,
				       length[12], &simPcrs[bankNum][12].digest.tssmax,
				       length[13], &simPcrs[bankNum][13].digest.tssmax,
				       length[14], &simPcrs[bankNum][14].digest.tssmax,
				       length[15], &simPcrs[bankNum][15].digest.tssmax,
				       length[16], &simPcrs[bankNum][16].digest.tssmax,
				       length[17], &simPcrs[bankNum][17].digest.tssmax,
				       length[18], &simPcrs[bankNum][18].digest.tssmax,
				       length[19], &simPcrs[bankNum][19].digest.tssmax,
				       length[20], &simPcrs[bankNum][20].digest.tssmax,
				       length[21], &simPcrs[bankNum][21].digest.tssmax,
				       length[22], &simPcrs[bankNum][22].digest.tssmax,
				       length[23], &simPcrs[bankNum][23].digest.tssmax,
				       0, NULL);
	    }
	    /* trace the boot aggregate */
	    if (rc == 0) {
		if (!noSpace) {
		    TSS_PrintAllLogLevel(LOGLEVEL_INFO, "\nboot aggregate:", 1,
					 bootAggregates[bankNum].digest.tssmax,
					 specIdEvent.digestSizes[bankNum].digestSize);
		}
		else {	/* print with no spaces */
		    uint32_t bp;
		    printf("\nboot aggregate: ");
		    for (bp = 0 ; bp < specIdEvent.digestSizes[bankNum].digestSize ; bp++) {
			printf("%02x", bootAggregates[bankNum].digest.tssmax[bp]);
		    }
		    printf("\n");
		}
	    }
	}
    }
    {
	if (tpm|| (sim && checkPcr)) {
	    TPM_RC rc1 = TSS_Delete(tssContext);
	    if (rc == 0) {
		rc = rc1;
	    }
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("eventextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eventextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}

/* pcrExtend() extends the event into the TPM

   If the event is EV_NO_ACTION -> StartupLocality, send a power cycle and a startup at the locality
   in the event, typically locality 3.  This initializes PCR 0  to 00....0003.

   Other EV_NO_ACTION events are skipped.

   Other events extend the PCR.
*/

static uint32_t pcrExtend(TSS_CONTEXT		*tssContext,
			  TCG_PCR_EVENT2 	*event2)
{
    uint32_t 			rc = 0;
    size_t 			i;
    PCR_Extend_In 		in;
    PCR_Read_In 		pcrReadIn;
    PCR_Read_Out 		pcrReadOut;

    if (rc == 0) {
	/* handle EV_NO_ACTION */
	if (event2->eventType == EV_NO_ACTION) {
	    /* startup locality sets PCR 0 to the locality */
	    if ((event2->pcrIndex == 0) &&
		/* StartupLocality in the event is NUL terminated, locality is one byte */
		(event2->eventSize == (sizeof("StartupLocality") + 1)) &&
		(memcmp(event2->event, "StartupLocality", sizeof("StartupLocality")) == 0)) {

		/* poewr cycle the TPM to prepare for startup */
		if (rc == 0) {		/* powerup platform port uses a separate TSS context */
		    rc = powerUp();
		}
		/* startup using the event specified locality */
		if (rc == 0) {
		    uint8_t locality = event2->event[sizeof("StartupLocality")];
		    rc = startup(tssContext, locality);
		}
	    }
	    /* other EV_NO_ACTION events are ignored */
	    else {
		return 0;
	    }
	}
	/* handle not EV_NO_ACTION */
	else {
	    in.pcrHandle = event2->pcrIndex;
	    in.digests = event2->digests;
	    rc = TSS_Execute(tssContext,
			     NULL, 
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_PCR_Extend,
			     TPM_RS_PW, NULL, 0,
			     TPM_RH_NULL, NULL, 0);
	}
    }
    /* for debug, read back and trace the PCR value after the extend */
    if ((rc == 0) && tssUtilsVerbose) {
	pcrReadIn.pcrSelectionIn.count = event2->digests.count;
	for (i = 0 ; i < event2->digests.count ; i++ ) {
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].hash =
		event2->digests.digests[i].hashAlg;
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].sizeofSelect = 3;
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].pcrSelect[0] = 0;
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].pcrSelect[1] = 0;
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].pcrSelect[2] = 0;
	    pcrReadIn.pcrSelectionIn.pcrSelections[i].pcrSelect[event2->pcrIndex / 8] =
		1 << (event2->pcrIndex % 8);
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&pcrReadOut,
			 (COMMAND_PARAMETERS *)&pcrReadIn,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
    }
    if ((rc == 0) && tssUtilsVerbose) {
	printf("PCR Read %u\n", event2->pcrIndex);
	for (i = 0 ; i < event2->digests.count ; i++ ) {
	    TSS_PrintAll("PCR digest",
			 pcrReadOut.pcrValues.digests[i].t.buffer,
			 pcrReadOut.pcrValues.digests[i].t.size);
	}
    }
    return rc;
}

static uint32_t powerUp(void)
{
    uint32_t 			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;

    if (rc == 0) {	/* use a separate context for the command port */
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");
    }
    /* power on platform */
    if (rc == 0) {
	rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
    }
    /* power on NV */
    if (rc == 0) {
	rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

static uint32_t startup(TSS_CONTEXT	*tssContext,
			uint8_t 	locality)
{
    uint32_t 		rc = 0;
    Startup_In 		in;
    char 		localityString[17];	/* 17 to suppress false warning */

    if (rc == 0) {
	memset(localityString, 0, sizeof(localityString));
	sprintf(localityString, "%.*u", 1, locality);
	TSS_SetProperty(tssContext, TPM_TRANSMIT_LOCALITY, localityString);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	in.startupType = TPM_SU_CLEAR;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Startup,
			 TPM_RH_NULL, NULL, 0);
    }
    TSS_SetProperty(tssContext, TPM_TRANSMIT_LOCALITY, NULL);
    return rc;
}

static void printUsage(void)
{
    printf("Usage: eventextend -if <measurement file> [-v]\n");
    printf("\n");
    printf("Extends a measurement file (binary) into a TPM or simulated PCRs\n");
    printf("Ignores most EV_NO_ACTION events, but handles StartupLocality.\n");
    printf("For -tpm, StartupLocality power cycles the TPM and sends TPM2_Startup\n");
    printf("at the specified locality.\n");
    printf("\n");
    printf("A typical use is -tpm, -sim, and -checkpcr to extend PCRs, calculate\n");
    printf("simulated PCRs, and compare the results.\n");
    printf("\n");
    printf("A typical use is just -v to parse and trace the event log details.\n");
    printf("\n");
    printf("\t-if\tfile containing the data to be extended\n");
    printf("\t[-nospec\tfile does not contain spec ID header (useful for incremental test)]\n");
    printf("\t[-tpm\textend TPM PCRs]\n");
    printf("\t[-sim\tcalculate simulated PCRs and boot aggregate]\n");
    printf("\t[-checkhash\tverify event log hashes]\n");
    printf("\t[-checkpcr\twith -sim verify PCR values]\n");
    printf("\t[-pcrmax\twith -sim, sets the highest PCR number to be used to calculate the\n"
	   "\t\tboot aggregate (default 7)]\n");
    printf("\t[-ns\tno space, no text, no newlines when tracing PCRs and boot aggregate]\n");
    printf("\t[-v\tverbose tracing]\n");
    printf("\n");
    exit(-1);
}

