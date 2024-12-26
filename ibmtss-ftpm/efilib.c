/********************************************************************************/
/*										*/
/*		     	EFI Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2021.						*/
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

/* This module parses UEFI pre-OS event logs.

   A typical usage is:

   TSS_EFIData_Init() - initialize the structure
   TSS_EFIData_ReadBuffer() - unmarshal an event into the structure
   TSS_EFIData_Free() - free the structure

   After TSS_EFIData_ReadBuffer(), the structure can be called with:

   TSS_EFIData_Trace() to pretty print the structure to stdout

   TSS_EFIData_ToJson() to output json in some TBD format and destination.  This has not been
   implemented.  There are some placeholders.

   See TCG PC Client Platform Firmware Profile Specification (PFP)
*/

#include <stddef.h>
#include <ctype.h>

#ifndef TPM_TSS_NO_OPENSSL
#include <openssl/x509.h>
#endif	/* TPM_TSS_NO_OPENSSL */

#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscrypto.h>

#include "eventlib.h"
#include "efilib.h"

/* Used for input sanity check.  Keep below ffff_ffff so that cast to uint32_t is safe */
#define EFI_LENGTH_MAX 0x100000

/* Some PFP event contents are not completely specified.  Use these functions to guess at the
   contents. */

static void isUCS2String(int *isUCS2, uint8_t *buffer, uint32_t length);
static void isAsciiString(int *isAscii, uint8_t *buffer, uint32_t length);

/*
  GUID Handling
*/

/* standard GUID values */

/* a5c059a1-94e4-4aa7-87b5-ab155c2bf072 */
#define EFI_CERT_X509_GUID				\
    {0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,	\
     0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
/* 8be4df61-93ca-11d2-aa0d-00e098032b8c */
#define EFI_GLOBAL_VARIABLE				\
    {0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,	\
     0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
/* d719b2cb-3d3a-4596-a3bc-dad00e67656f */
#define EFI_IMAGE_SECURITY_DATABASE_GUID		\
    {0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45,	\
     0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}
/* f2fd1544-9794-4a2c-992e-e5bbcf20e394 */
#define SMBIOS3_TABLE_GUID				\
    {0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a,	\
     0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}
/* 7facc7b6-127f-4e9c-9c5d-080f98994345 */
#define LENOVO2_GUID					\
    {0xb6, 0xc7, 0xac, 0x7f, 0x7f, 0x12, 0x9c, 0x4e,	\
     0x9c, 0x5d, 0x08, 0x0f, 0x98, 0x99, 0x43, 0x45}
/* 77fa9abd-0359-4d32-bd60-28f4e78f784b */
#define MICROSOFT_GUID					\
    {0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 	\
     0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}
/* 3cc24e96-22c7-41d8-8863-8e39dcdcc2cf */
#define LENOVO_GUID					\
    {0x96, 0x4e, 0xc2, 0x3c, 0xc7, 0x22, 0xd8, 0x41, 	\
     0x88, 0x63, 0x8e, 0x39, 0xdc, 0xdc, 0xc2, 0xcf}
/* 70564dce-9afc-4ee3-85fc-949649d7e45c */
#define DELL_PK_SIGNING_KEY				\
    {0xce, 0x4d, 0x56, 0x70, 0xfc, 0x9a, 0xe3, 0x4e,	\
     0x85, 0xfc, 0x94, 0x96, 0x49, 0xd7, 0xe4, 0x5c}
/* c1c41626-504c-4092-aca9-41f936934328	*/
#define SHA256_GUID					\
    {0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,	\
     0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}
#define EFI_MP_SERVICES_PROTOCOL_GUID			\
    {0x05, 0xa6, 0xdd, 0x3f, 0x6e, 0xa7, 0x46, 0x4f,	\
     0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08}
/* c12a7328-f81f-11d2-ba4b-00a0c93ec93b */
#define EFI_SYSTEM_PARTITION_GUID			\
    {0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,	\
     0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b} 
/* e3c9e316-0b5c-4db8-817d-f92df00215ae */
#define MICROSOFT_RESERVED_PARTITION_GUID		\
    {0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d,	\
     0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae}
/* ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 */
#define BASIC_DATA_PARTITION_GUID			\
    {0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,	\
     0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7}
/* de94bba4-06d1-4d40-a16a-bfd50179d6ac */
#define WINDOWS_RECOVERY_ENVIRONMENT_GUID		\
    {0xa4, 0xbb, 0x94, 0xde, 0xd1, 0x06, 0x40, 0x4d,	\
     0xa1, 0x6a, 0xbf, 0xd5, 0x01, 0x79, 0xd6, 0xac}
/* 0fc63daf-8483-4772-8e79-3d69d8477de4 */
#define LINUX_FILESYSTEM_DATA_GUID			\
    {0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,	\
     0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}
/* 21686148-6449-6e6f-744e-656564454649 */
#define BIOS_BOOT_PARTITION_GUID			\
    {0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6f, 0x6e,	\
	    0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49}
/* 605dab50-e046-4300-abb6-3dd810dd8b23 */
#define SHIM_LOCK_GUID					\
    {0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43,	\
	    0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23}

#if 0	/* future GUIDs to be supported */
#define SMBIOS_TABLE_GUID    			"eb9d2d31-2d88-11d3-9a16-0090273fc14d"
#define EFI_ACPI_20_TABLE_GUID 			"8868e871-e4f1-11d3-bc22-0080c73c8881"
#define ACPI_TABLE_GUID    			"eb9d2d30-2d88-11d3-9a16-0090273fc14d"
#define SAL_SYSTEM_TABLE_GUID    		"eb9d2d32-2d88-11d3-9a16-0090273fc14d"
#define MPS_TABLE_GUID    			"eb9d2d2f-2d88-11d3-9a16-0090273fc14d"
#define EFI_JSON_CONFIG_DATA_TABLE_GUID		"87367f87-1119-41ce-aaec-8be0111f558a"
#define EFI_JSON_CAPSULE_DATA_TABLE_GUID    	"35e7a725-8dd2-4cac-8011-33cda8109056"
#define EFI_JSON_CAPSULE_RESULT_TABLE_GUID    	"dbc461c3-b3de-422a-b9b4-9886fd49a1e5"
/* these may not be endian correct */
#define GRUB_EFI_CONSOLE_CONTROL_GUID		"f42f7782-012e-4c12-9956-49f94304f721"
#define GRUB_EFI_PCI_IO_GUID			"4cf5b200-68b8-4ca5-9eec-b23e3f50029a"
#define GRUB_EFI_PCI_ROOT_IO_GUID		"2F707EBB-4A1A-11d4-9A38-0090273FC14D"
#define GRUB_EFI_LOADED_IMAGE_GUID		"5b1b31a1-9562-11d2-8e3f-00a0c969723b"
#define GRUB_EFI_DISK_IO_GUID			"ce345171-ba0b-11d2-8e4f-00a0c969723b"
#define GRUB_EFI_BLOCK_IO_GUID			"964e5b21-6459-11d2-8e39-00a0c969723b"
#define GRUB_EFI_DEVICE_PATH_GUID		"09576e91-6d3f-11d2-8e39-00a0c969723b"
#define GRUB_EFI_DEVICE_PATH_FROM_TEXT_GUID	"05c99a21-c70f-4ad2-8a5f-35df3343f51e"
#define GRUB_EFI_GRAPHICS_OUTPUT_GUID		"042a9de-23dc-4a38- 96fb-7aded080516a"
#define GRUB_EFI_UGA_DRAW_GUID			"982c298b-f4fa-41cb-b838-77aa688fb839"
#define GRUB_EFI_UGA_IO_GUID			"61a4d49e-6f68-4f1b-b922-a86eed0b07a2"
#define GRUB_EFI_SIMPLE_FILE_SYSTEM_GUID	"964e5b22-6459-11d2-8e39-00a0c969723b"
#define GRUB_EFI_SERIAL_IO_GUID			"bb25cf6f-f1d4-11d2-9a0c-0090273Fc1fd"
#endif

/* GUID data types - used to map content type */

#define GUID_TYPE_UNSUPPORTED	0
#define GUID_TYPE_X509_CERT 	1
#define GUID_TYPE_SHA256 	2

/* This table maps GUID to the data type.  It includes the text name of the GUID for tracing. */

typedef struct {
    uint8_t guidBin[16];	/* binary */
    uint32_t type;
    const char *guidText;	/* trace text */
} GUID_TABLE;

const GUID_TABLE guidTable [] =
    {
     {EFI_CERT_X509_GUID,
      GUID_TYPE_X509_CERT,
      "EFI_CERT_X509_GUID"},
     {EFI_GLOBAL_VARIABLE,
      GUID_TYPE_UNSUPPORTED,
      "EFI_GLOBAL_VARIABLE_GUID"},
     {EFI_IMAGE_SECURITY_DATABASE_GUID,
      GUID_TYPE_X509_CERT,
      "EFI_IMAGE_SECURITY_DATABASE_GUID"},
     {SMBIOS3_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SMBIOS3_TABLE_GUID"},
     {LENOVO2_GUID,
      GUID_TYPE_UNSUPPORTED,
      "LENOVO2_GUID"},
     {MICROSOFT_GUID,
      GUID_TYPE_X509_CERT,
      "MICROSOFT_GUID"},
     {LENOVO_GUID,
      GUID_TYPE_UNSUPPORTED,
      "LENOVO_GUID"},
     {DELL_PK_SIGNING_KEY,
      GUID_TYPE_UNSUPPORTED,
      "DELL_PK_SIGNING_KEY_GUID"},
     {SHA256_GUID,
      GUID_TYPE_SHA256,
      "SHA256_GUID"},
     {EFI_MP_SERVICES_PROTOCOL_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_MP_SERVICES_PROTOCOL_GUID"},
     {EFI_SYSTEM_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_SYSTEM_PARTITION_GUID"},
     {MICROSOFT_RESERVED_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "MICROSOFT_RESERVED_PARTITION_GUID"},
     {BASIC_DATA_PARTITION_GUID,
      GUID_TYPE_UNSUPPORTED,
      "BASIC_DATA_PARTITION_GUID"},
     {WINDOWS_RECOVERY_ENVIRONMENT_GUID,
     GUID_TYPE_UNSUPPORTED,
     "WINDOWS_RECOVERY_ENVIRONMENT_GUID"},
     {LINUX_FILESYSTEM_DATA_GUID,
     GUID_TYPE_UNSUPPORTED,
     "LINUX_FILESYSTEM_DATA_GUID"},
     {BIOS_BOOT_PARTITION_GUID,
     GUID_TYPE_UNSUPPORTED,
     "BIOS_BOOT_PARTITION_GUID"},
     {SHIM_LOCK_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SHIM_LOCK_GUID"},
#if 0
     {EFI_ACPI_20_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_ACPI_20_TABLE_GUID"},
     {ACPI_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "ACPI_TABLE_GUID"},
     {SAL_SYSTEM_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SAL_SYSTEM_TABLE_GUID"},
     {SMBIOS_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "SMBIOS_TABLE_GUID"},
     {MPS_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "MPS_TABLE_GUID"},
     {EFI_JSON_CONFIG_DATA_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CONFIG_DATA_TABLE_GUID"},
     {EFI_JSON_CAPSULE_DATA_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CAPSaULE_DATA_TABLE_GUID"},
     {EFI_JSON_CAPSULE_RESULT_TABLE_GUID,
      GUID_TYPE_UNSUPPORTED,
      "EFI_JSON_CAPSULE_RESULT_TABLE_GUID"},
#endif
    };

static uint32_t TSS_EFI_GetGuidIndex(size_t *index, const uint8_t *guidBin);

static void guid_printf(const char *msg, uint8_t *guid);

/* guid_printf() traces the input GUID, first as hexacsii and then as text.

   It prepends msg to ther hexascii trace.  msg must not be NULL but can be "".
   guid must be 16 bytes;
*/

static void guid_printf(const char *msg, uint8_t *guid)
{
    int rc;
    size_t index;

    printf("  %s: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
	   msg,
	   guid[3],guid[2],guid[1],guid[0],
	   guid[5],guid[4],
	   guid[7],guid[6],
	   guid[8],guid[9],
	   guid[10],guid[11],guid[12],guid[13],guid[14],guid[15]);
    /* if the GUID is known, trace the GUID as text */
    rc = TSS_EFI_GetGuidIndex(&index, guid);
    if (rc == 0) {
	printf("    %s\n", guidTable[index].guidText);
    }
    return;
}

/* TSS_EFI_GetGuidIndex() gets the index into the GUID table for the GUID array guidBin

   Returns TSS_RC_NOT_IMPLEMENTED for an unimplemeted GUID.
*/

static uint32_t TSS_EFI_GetGuidIndex(size_t *index, const uint8_t *guidBin)
{
    for (*index = 0 ;
	 *index < sizeof(guidTable) / sizeof(GUID_TABLE) ;
	 (*index)++) {
	if (memcmp(guidTable[*index].guidBin, guidBin, 16) == 0) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/*
  UC16 String handling
*/

/* Standard UEFI UC16 Variable Name strings */

const unsigned char unknown[] = "\x00";
const unsigned char SecureBoot[] =
    "\x53\x00\x65\x00\x63\x00\x75\x00\x72\x00\x65\x00"
    "\x42\x00\x6f\x00\x6f\x00\x74";
const unsigned char AuditMode[] =
    "\x41\x00\x75\x00\x64\x00\x69\x00\x74\x00\x4d\x00"
    "\x6f\x00\x64\x00\x65";
const unsigned char DeployedMode[] =
    "\x44\x00\x65\x00\x70\x00\x6c\x00\x6f\x00\x79\x00"
    "\x65\x00\x64\x00\x4d\x00\x6f\x00\x64\x00\x65";
const unsigned char setupmode[] =
    "\x53\x00\x65\x00\x74\x00\x75\x00\x70\x00\x4d\x00"
    "\x6f\x00\x64\x00\x65";
const unsigned char PK[]  = "\x50\x00\x4b"; 
const unsigned char KEK[] = "\x4b\x00\x45\x00\x4b";
const unsigned char db[]  = "\x64\x00\x62";
const unsigned char dbr[] = "\x64\x00\x62\x00\x72";
const unsigned char dbt[] = "\x64\x00\x62\x00\x74";
const unsigned char dbx[] = "\x64\x00\x62\x00\x78";
const unsigned char BootOrder[] =
    "\x42\x00\x6f\x00\x6f\x00\x74\x00\x4f\x00\x72\x00"
    "\x64\x00\x65\x00\x72";
const unsigned char Shim[] = "\x53\x00\x68\x00\x69\x00\x6d";
const unsigned char MokList[] = "\x4d\x00\x6f\x00\x6b\x00\x4c\x00\x69\x00\x73\x00\x74";
const unsigned char MokListX[] = "\x4d\x00\x6f\x00\x6b\x00\x4c\x00\x69\x00\x73\x00\x74\x00\x58";

/* This table maps UC16 Variable names to this implementation structure tags */

typedef struct {
    const unsigned char *name;
    uint32_t nameLength;
    int tag;
} TAG_TABLE;

const TAG_TABLE tagTable [] =
    {
     {unknown,
      sizeof(unknown),
      TSS_VAR_UNKNOWN},
     {SecureBoot,
      sizeof(SecureBoot),
      TSS_VAR_SECUREBOOT},
     {AuditMode,
      sizeof(AuditMode),
      TSS_VAR_AUDITMODE},
     {DeployedMode,
      sizeof(DeployedMode),
      TSS_VAR_DEPLOYEDMODE},
     {setupmode,
      sizeof(setupmode),
      TSS_VAR_SETUPMODE},
     {PK,
      sizeof(PK),
      TSS_VAR_PK},
     {KEK,
      sizeof(KEK),
      TSS_VAR_KEK},
     {db,
      sizeof(db),
      TSS_VAR_DB},
     {dbx,
      sizeof(dbx),
      TSS_VAR_DBX},
     {dbt,
      sizeof(dbt),
      TSS_VAR_DBT},
     {dbr,
      sizeof(dbr),
      TSS_VAR_DBR},
     {BootOrder,
      sizeof(BootOrder),
      TSS_VAR_BOOTORDER},
     {Shim,
      sizeof(Shim),
      TSS_VAR_SHIM},
     {MokList,
      sizeof(MokList),
      TSS_VAR_MOKLIST},
     {MokListX,
      sizeof(MokListX),
      TSS_VAR_MOKLISTX},
     };

static void TSS_EFI_GetNameIndex(size_t *index,
				 const uint8_t *name, uint64_t nameLength);

/* TSS_EFI_GetTagIndex() gets the index into the tag table for the name.

   If the name does't match, returns index 0, which is the unknown name.
*/

static void TSS_EFI_GetNameIndex(size_t *index,
				 const uint8_t *name,
				 uint64_t nameLength)	/* half the total bytes in array */
{
    int m1 = 0;
    int m2 = 0;
    for (*index = 0 ;
	 *index < sizeof(tagTable) / sizeof(TAG_TABLE)  ;
	 (*index)++) {

	/* length match */
	m1 = (nameLength * 2) == tagTable[*index].nameLength;
	if (m1) {
	    /* string match */
	    m2 = memcmp(name, tagTable[*index].name, (size_t)(nameLength * 2)) == 0;
	}
	if (m1 && m2) {
	    return;
	}
    }
    *index = 0;		/* no match, unknown */
    return;
}

static void ucs2_printf(const char *msg, uint8_t *ucs2, uint32_t length);

/* Print UCS-2 character string.

   This function doesn't support true UCS-2.  It assumes that odd bytes are all zero.

   length is number of UCS-2 characters, which is the number of bytes in the ucs2 arrray.  ucs2
   is a ucs2 array to be printed, not including an extra nul terminator.

   It prepends msg to ther hexascii trace.  msg must not be NULL but can be "".
*/

static void ucs2_printf(const char *msg, uint8_t *ucs2, uint32_t length)
{
    uint32_t i;

    printf("  %s", msg);
    for (i = 0; i < length ; i+=2) {
        printf("%c", ucs2[i]);
    }
    printf("\n");
    return;
}

/* isUCS2String() guesses whether the buffer is printable UCS-2.  Checks for an even number of bytes
   and every odd byte 0x00.
 */

static void isUCS2String(int *isUCS2, uint8_t *buffer, uint32_t length)
{
    uint32_t i;

    if ((length % 2) != 0) {
	*isUCS2 = 0;
	return;
    }
    for (i = 1 ; i < length ; i+=2) {
	if (buffer[i] != 0x00) {
	    *isUCS2 = 0;	/* UCS-2 typically has all odd bytes 0 */
	    return;
	}
    }
    *isUCS2 = 1;
    return;
}

/* isAsciiString() checks whether all bytes in the buffer are printable.

   length does not include a nul terminator
*/

static void isAsciiString(int *isAscii, uint8_t *buffer, uint32_t length)
{
    uint32_t i;
    for (i = 1 ; i < length ; i++) {
	if (!isprint((int)buffer[i])) {
	    *isAscii = 0;
	    return;
	}
    }
    *isAscii = 1;
    return;
}


uint32_t TSS_UCS2_Unmarshal(uint8_t **ucs2,
			    uint32_t *DescriptionLength,
			    uint8_t **event, uint32_t *eventSize);

/* TSS_UCS2_Unmarshal() copies the event to a malloc'ed ucs2, not including the NUL terminator.

   It returns the length, which is half the number of bytes in ucs2
*/

uint32_t TSS_UCS2_Unmarshal(uint8_t **ucs2,		/* freed by caller */
			    uint32_t *DescriptionLength,
			    uint8_t **event, uint32_t *eventSize)
{
    uint32_t i;
    uint32_t bytes;	/* bytes to malloc and store from event */
    int foundNul = 0;

    *DescriptionLength = 0;
    /* count the number of UCS-2 bytes */
    for (i = 0 ; i < *eventSize ; i+= 2) {
	if ((i+1) > *eventSize) {
	    return TSS_RC_INSUFFICIENT_BUFFER;	/* handle odd number of event bytes case */
	}
	if (((*event)[i] == 0) && ((*event)[i+1] == 0)) {
	    foundNul = 1;
	    break;
	}
    }
    if (!foundNul) {
	return TSS_RC_INSUFFICIENT_BUFFER;
    }
    bytes = i;
    *DescriptionLength = i/2;
    *ucs2 = malloc(bytes);
    if (*ucs2 == NULL) {
	return TSS_RC_OUT_OF_MEMORY;
    }
    for (i = 0 ; i < bytes ; i++) {
	(*ucs2)[i] = **event;
	*event += 1;
	*eventSize -= 1;
    }
    /* index past the NUL */
    *event += 2;
    *eventSize -= 2;
    return 0;
}

/*
  EV_COMPACT_HASH Handler
*/

/* EV_COMPACT_HASH post-OS (PCR 11) Values, from Microsoft
 
 */

#define EV_COMPACT_HASH_PRE10_SUCCESS		\
    {0x00, 0x00, 0x00, 0x00}
#define EV_COMPACT_HASH_PRE10_DEBUG		\
    {0x01, 0x00, 0x00, 0x00}
#define EV_COMPACT_HASH_PRE10_ERROR		\
    {0x02, 0x00, 0x00, 0x00}
#define EV_COMPACT_HASH_WIN10_SUCCESS		\
    {0x10, 0x00, 0x00, 0x00}
#define EV_COMPACT_HASH_WIN10_UNSAFE		\
    {0xff, 0xff, 0x00, 0x00}

/* This table maps the EV_COMPACT_HASH values to text */

typedef struct {
    uint8_t value[4];
    const char *text;
} EV_COMPACT_HASH_TABLE;

const EV_COMPACT_HASH_TABLE compactHashTable [] =
    {
     {EV_COMPACT_HASH_PRE10_SUCCESS,
      "Pre-Windows 10 Bitlocker success"},
     {EV_COMPACT_HASH_PRE10_DEBUG,
      "Pre-Windows 10 Bitlocker detected debugger"},
     {EV_COMPACT_HASH_PRE10_ERROR,
      "Pre-Windows 10 Error"},
     {EV_COMPACT_HASH_WIN10_SUCCESS,
      "Windows 10 Bitlocker success"},
     {EV_COMPACT_HASH_WIN10_UNSAFE,
      "Windows 10 Unsafe Windows launch"},
    };

static uint32_t TSS_EFI_GetCompactHashIndex(size_t *index,
					    const uint8_t *value);

/* TSS_EFI_GetCompactHashIndex() matches the value to the EV_COMPACT_HASH_TABLE.

   Returns TSS_RC_NOT_IMPLEMENTED on no match,
*/

static uint32_t TSS_EFI_GetCompactHashIndex(size_t *index,
					    const uint8_t *value)
{
    int m1;
    for (*index = 0 ;
	 *index < sizeof(compactHashTable) / sizeof(EV_COMPACT_HASH_TABLE)  ;
	 (*index)++) {

	m1 = memcmp(value,
		    compactHashTable[*index].value,
		    sizeof(((EV_COMPACT_HASH_TABLE *)NULL)->value)) == 0;
	if (m1) {
	    return 0;
	}
    }
    /* no match */
    return TSS_RC_NOT_IMPLEMENTED;
}

/*
  Device Path Handler
*/

/* Used for EV_EFI_BOOT_SERVICES_DRIVER, EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_VARIABLE_BOOT */

/* EFI_DEVICE_PATH_PROTOCOL Type Table - mapping from Type to SubType Handler */

typedef uint32_t (*TSS_EFIDevicePath_ReadBuffer_Function_t)(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							    uint8_t **event,
							    uint32_t *eventSize);
typedef void     (*TSS_EFIDevicePath_Trace_Function_t)(TSS_UEFI_DEVICE_PATH *uefiDevicePath);

typedef struct {
    uint8_t type;
    const char *text;
    TSS_EFIDevicePath_ReadBuffer_Function_t 	readBufferFunction;
    TSS_EFIDevicePath_Trace_Function_t		traceFunction;
} EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE;

static uint32_t TSS_EFI_GetDevicePathIndex(size_t *index, const uint8_t type,
					   size_t tableSize,
					   const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE *table);

/* TSS_EFI_GetDevicePathIndex() returns an index into several tables containing
   EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE entries.

   The 'type' parameter is the key.  It is sometimes the Device Path Type, sometimes the SubType;

   Returns TSS_RC_NOT_IMPLEMENTED if 'type' is not found.
*/

static uint32_t TSS_EFI_GetDevicePathIndex(size_t *index, const uint8_t type,
					   size_t tableSize,
					   const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE *table)
{
    int m1;
#if 0
    printf("TSS_EFI_GetDevicePathIndex: type %02x tableSize %lu iterate %lu\n",
	   type, tableSize, tableSize / sizeof(EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE));
#endif
    for (*index = 0 ;
	 *index < tableSize / sizeof(EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE) ;
	 (*index)++) {
#if 0
	printf("TSS_EFI_GetDevicePathIndex: type %02x index %lu table type %02x\n",
	       type, *index, table[*index].type);
#endif
	m1 = (type == table[*index].type);
	if (m1) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/* From UEFI 10.3.1 Table 44 Generic Device Path Structures */

#define EFI_DEVICE_PATH_TYPE_HW  	0x01
#define EFI_DEVICE_PATH_TYPE_ACPI 	0x02
#define EFI_DEVICE_PATH_TYPE_MSG  	0x03
#define EFI_DEVICE_PATH_TYPE_MEDIA 	0x04
#define EFI_DEVICE_PATH_TYPE_BIOS 	0x05
#define EFI_DEVICE_PATH_TYPE_END 	0x7F

static uint32_t TSS_EfiDevicePathHw_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
					       uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						 uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsg_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMedia_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathBios_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						 uint8_t **event, uint32_t *eventSize);
#endif
static uint32_t TSS_EfiDevicePathEnd_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						uint8_t **event, uint32_t *eventSize);

static void TSS_EfiDevicePathHw_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathMsg_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathMedia_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathBios_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif
static void TSS_EfiDevicePathEnd_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);

const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE efiDevicePathProtocolTypeTable [] =
    {
     {EFI_DEVICE_PATH_TYPE_HW,
      "Hardware Device Path",
      TSS_EfiDevicePathHw_ReadBuffer,
      TSS_EfiDevicePathHw_Trace},
     {EFI_DEVICE_PATH_TYPE_ACPI,
      "ACPI Device Path",
      TSS_EfiDevicePathAcpi_ReadBuffer,
      TSS_EfiDevicePathAcpi_Trace},
     {EFI_DEVICE_PATH_TYPE_MSG,
      "Messaging Device Path",
      TSS_EfiDevicePathMsg_ReadBuffer,
      TSS_EfiDevicePathMsg_Trace},
     {EFI_DEVICE_PATH_TYPE_MEDIA,
      "Media Device Path",
      TSS_EfiDevicePathMedia_ReadBuffer,
      TSS_EfiDevicePathMedia_Trace},
#if 0
     {EFI_DEVICE_PATH_TYPE_BIOS,
      "BIOS Boot Specification Device Path",
      TSS_EfiDevicePathBios_ReadBuffer,
      TSS_EfiDevicePathBios_Trace},
#endif
     {EFI_DEVICE_PATH_TYPE_END,
      "End of Hardware Device Path",
      TSS_EfiDevicePathEnd_ReadBuffer,
      TSS_EfiDevicePathEnd_Trace},
    };

/* From UEFI 10.3.2 Hardware Device Path - Type 1 SubTypes */

#define EFI_DEVICE_PATH_HW_SUBTYPE_PCI		1
#define EFI_DEVICE_PATH_HW_SUBTYPE_PCCARD	2
#define EFI_DEVICE_PATH_HW_SUBTYPE_MMAP		3
#define EFI_DEVICE_PATH_HW_SUBTYPE_VENDOR	4
#define EFI_DEVICE_PATH_HW_SUBTYPE_CTRLR	5
#define EFI_DEVICE_PATH_HW_SUBTYPE_BMC		6

static uint32_t TSS_UefiDevicePathList_ReadBuffer(TSS_UEFI_DEVICE_PATH **UefiDevicePath,
						  uint32_t *UefiDevicePathCount,
						  uint8_t *devicePath,
						  uint32_t lengthOfDevicePath);

static uint32_t TSS_EfiDevicePathHwPCI_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathHwPCCARD_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						     uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathHwMMAP_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize);
#endif
static uint32_t TSS_EfiDevicePathHwVENDOR_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						     uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathHwCTRLR_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathHwBMC_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize);
#endif

static void TSS_EfiDevicePathHwPCI_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathHwPCCARD_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathHwMMAP_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif
static void TSS_EfiDevicePathHwVENDOR_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePatHwCTRLR_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathHwBMC_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif

const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE efiDevicePathProtocolHwTypeTable [] =
    {
     {EFI_DEVICE_PATH_HW_SUBTYPE_PCI,
      "PCI",
      TSS_EfiDevicePathHwPCI_ReadBuffer,
      TSS_EfiDevicePathHwPCI_Trace},
#if 0
     {EFI_DEVICE_PATH_HW_SUBTYPE_PCCARD,
      "PCCARD",
      TSS_EfiDevicePathHwPCCARD_ReadBuffer,
      TSS_EfiDevicePathHwPCCARD_Trace},
     {EFI_DEVICE_PATH_HW_SUBTYPE_MMAP,
      "Memory Mapped",
      TSS_EfiDevicePathHwMMAP_ReadBuffer,
      TSS_EfiDevicePathHwMMAP_Trace},
#endif
     {EFI_DEVICE_PATH_HW_SUBTYPE_VENDOR,
      "Vendor",
      TSS_EfiDevicePathHwVENDOR_ReadBuffer,
      TSS_EfiDevicePathHwVENDOR_Trace},
#if 0
     {EFI_DEVICE_PATH_HW_SUBTYPE_CTRLR,
      "Controller",
      TSS_EfiDevicePathHwCTRLR_ReadBuffer,
      TSS_EfiDevicePathHwCTRLR_Trace},
     {EFI_DEVICE_PATH_HW_SUBTYPE_BMC,
      "BMC",
      TSS_EfiDevicePathHwBMC_ReadBuffer,
      TSS_EfiDevicePathHwBMC_Trace},
#endif
    };

/* From UEFI 10.3.3 ACPI Device Path  - Type 2 SubTypes */

#define EFI_DEVICE_PATH_ACPI_SUBTYPE_ACPI	0x01
#define EFI_DEVICE_PATH_ACPI_SUBTYPE_EXPACPI	0x02
#define EFI_DEVICE_PATH_ACPI_SUBTYPE_ADR	0x03
#define EFI_DEVICE_PATH_ACPI_SUBTYPE_NVDIMM	0x04

static uint32_t TSS_EfiDevicePathAcpiSubAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathAcpiExpAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathAcpiAdr_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathAcpiNvdimm_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize);
#endif

static void TSS_EfiDevicePathAcpiSubAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathAcpiExpAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathAcpiAdr_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathAcpiNvdimm_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif

const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE efiDevicePathProtocolAcpiTypeTable [] =
    {
     {EFI_DEVICE_PATH_ACPI_SUBTYPE_ACPI,
      "ACPI Device Path",
      TSS_EfiDevicePathAcpiSubAcpi_ReadBuffer,
      TSS_EfiDevicePathAcpiSubAcpi_Trace},
#if 0
     {EFI_DEVICE_PATH_ACPI_SUBTYPE_EXPACPI,
      "Expanded ACPI Device Path",
      TSS_EfiDevicePathAcpiExpAcpi_ReadBuffer,
      TSS_EfiDevicePathAcpiExpAcpi_Trace},
     {EFI_DEVICE_PATH_ACPI_SUBTYPE_ADR,
      "_ADR Device Path",
      TSS_EfiDevicePathAcpiAdr_ReadBuffer,
      TSS_EfiDevicePathAcpiAdr_Trace},
     {EFI_DEVICE_PATH_ACPI_SUBTYPE_NVDIMM,
      "NVDIMM Device",
      TSS_EfiDevicePathAcpiNvdimm_ReadBuffer,
      TSS_EfiDevicePathAcpiNvdimm_Trace},
#endif
    };

/* From UEFI 10.3.4 Messaging Device Path  - Type 3 SubTypes */

/* UEFI code uses the prefix MSG_ */

#define EFI_DEVICE_PATH_MSG_ATAPI_DP              	0x01
#define EFI_DEVICE_PATH_MSG_SCSI_DP               	0x02
#define EFI_DEVICE_PATH_MSG_FIBRECHANNEL_DP       	0x03
#define EFI_DEVICE_PATH_MSG_1394_DP               	0x04
#define EFI_DEVICE_PATH_MSG_USB_DP                	0x05
#define EFI_DEVICE_PATH_MSG_I2O_DP                	0x06
#define EFI_DEVICE_PATH_MSG_INFINIBAND_DP         	0x09
#define EFI_DEVICE_PATH_MSG_VENDOR_DP             	0x0a
#define EFI_DEVICE_PATH_MSG_MAC_ADDR_DP           	0x0b
#define EFI_DEVICE_PATH_MSG_IPv4_DP               	0x0c
#define EFI_DEVICE_PATH_MSG_IPv6_DP               	0x0d
#define EFI_DEVICE_PATH_MSG_UART_DP               	0x0e
#define EFI_DEVICE_PATH_MSG_USB_CLASS_DP          	0x0f
#define EFI_DEVICE_PATH_MSG_USB_WWID_DP           	0x10
#define EFI_DEVICE_PATH_MSG_DEVICE_LOGICAL_UNIT_DP  	0x11
#define EFI_DEVICE_PATH_MSG_SATA_DP               	0x12
#define EFI_DEVICE_PATH_MSG_ISCSI_DP              	0x13
#define EFI_DEVICE_PATH_MSG_VLAN_DP               	0x14
#define EFI_DEVICE_PATH_MSG_FIBRECHANNELEX_DP     	0x15
#define EFI_DEVICE_PATH_MSG_SASEX_DP              	0x16
#define EFI_DEVICE_PATH_MSG_NVME_NAMESPACE_DP     	0x17
#define EFI_DEVICE_PATH_MSG_URI_DP                	0x18
#define EFI_DEVICE_PATH_MSG_UFS_DP                	0x19
#define EFI_DEVICE_PATH_MSG_SD_DP                 	0x1A
#define EFI_DEVICE_PATH_MSG_BLUETOOTH_DP     		0x1b
#define EFI_DEVICE_PATH_MSG_WIFI_DP               	0x1C
#define EFI_DEVICE_PATH_MSG_EMMC_DP                 	0x1D
#define EFI_DEVICE_PATH_MSG_BLUETOOTH_LE_DP       	0x1E
#define EFI_DEVICE_PATH_MSG_DNS_DP                	0x1F
#define EFI_DEVICE_PATH_MSG_NVDIMM_NAMESPACE_DP        	0x20

static uint32_t TSS_EfiDevicePathMsgScsi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgUsb_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgUsbClass_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgSata_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgNvme_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgMac_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgIpv4_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgIpv6_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgUri_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMsgVendor_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						      uint8_t **event, uint32_t *eventSize);

static void     TSS_EfiDevicePathMsgScsi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgUsb_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgUsbClass_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgSata_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgNvme_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void 	TSS_EfiDevicePathMsgMac_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgIpv4_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgIpv6_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgUri_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_EfiDevicePathMsgVendor_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);

const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE efiDevicePathProtocolMsgTypeTable [] =
    {
     {EFI_DEVICE_PATH_MSG_SCSI_DP,
      "Message Device Path SCSI ",
      TSS_EfiDevicePathMsgScsi_ReadBuffer,
      TSS_EfiDevicePathMsgScsi_Trace},
     {EFI_DEVICE_PATH_MSG_USB_DP,
      "Message Device Path USB",
      TSS_EfiDevicePathMsgUsb_ReadBuffer,
      TSS_EfiDevicePathMsgUsb_Trace},
     {EFI_DEVICE_PATH_MSG_USB_CLASS_DP,
      "Message Device Path USB Class",
      TSS_EfiDevicePathMsgUsbClass_ReadBuffer,
      TSS_EfiDevicePathMsgUsbClass_Trace},
     {EFI_DEVICE_PATH_MSG_NVME_NAMESPACE_DP,
      "Message Device Path NVME",
      TSS_EfiDevicePathMsgNvme_ReadBuffer,
      TSS_EfiDevicePathMsgNvme_Trace},
     {EFI_DEVICE_PATH_MSG_SATA_DP,
      "Message Device Path SATA ",
      TSS_EfiDevicePathMsgSata_ReadBuffer,
      TSS_EfiDevicePathMsgSata_Trace},
     {EFI_DEVICE_PATH_MSG_MAC_ADDR_DP,
      "Message Device Path MAC Address",
      TSS_EfiDevicePathMsgMac_ReadBuffer,
      TSS_EfiDevicePathMsgMac_Trace},
     {EFI_DEVICE_PATH_MSG_IPv4_DP,
      "Message Device Path IPv4",
      TSS_EfiDevicePathMsgIpv4_ReadBuffer,
      TSS_EfiDevicePathMsgIpv4_Trace},
     {EFI_DEVICE_PATH_MSG_IPv6_DP,
      "Message Device Path IPv6",
      TSS_EfiDevicePathMsgIpv6_ReadBuffer,
      TSS_EfiDevicePathMsgIpv6_Trace},
     {EFI_DEVICE_PATH_MSG_URI_DP,
      "Message Device Path URI",
      TSS_EfiDevicePathMsgUri_ReadBuffer,
      TSS_EfiDevicePathMsgUri_Trace},
     {EFI_DEVICE_PATH_MSG_VENDOR_DP,
      "Message Device Path Vendor",
      TSS_EfiDevicePathMsgVendor_ReadBuffer,
      TSS_EfiDevicePathMsgVendor_Trace},
   };

/* From UEFI 10.3.5 Media Device Path  - Type 4 SubTypes */

#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_HD	0x01
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_CDROM	0x02
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_VENDOR	0x03
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_FILE	0x04
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_MEDIA	0x05
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_PIWG_FILE	0x06
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_PIWG_FW	0x07
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_OFFSET	0x08
#define EFI_DEVICE_PATH_MEDIA_SUBTYPE_RAMDISK	0x09

static uint32_t TSS_EfiDevicePathMediaHd_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathMediaCdrom_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMediaVendor_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
#endif
static uint32_t TSS_EfiDevicePathMediaFile_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathMediaMedia_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize);
#endif
static uint32_t TSS_EfiDevicePathMediaPiwgFile_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							  uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMediaPiwgFw_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiDevicePathMediaOffset_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize);
#if 0
static uint32_t TSS_EfiDevicePathMediaRamdisk_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							 uint8_t **event, uint32_t *eventSize);
#endif

static void TSS_EfiDevicePathMediaHd_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathMediaCdrom_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathMediaVendor_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif
static void TSS_EfiDevicePathMediaFile_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathMediaMedia_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif
static void TSS_EfiDevicePathMediaPiwgFile_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathMediaPiwgFw_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void TSS_EfiDevicePathMediaOffset_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#if 0
static void TSS_EfiDevicePathMediaRamdisk_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
#endif

const EFI_DEVICE_PATH_PROTOCOL_TYPE_TABLE efiDevicePathProtocolMediaTypeTable [] =
    {
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_HD,
      "Media Device Path HD",
      TSS_EfiDevicePathMediaHd_ReadBuffer,
      TSS_EfiDevicePathMediaHd_Trace},
#if 0
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_CDROM,
      "Media Device Path CDROM",
      TSS_EfiDevicePathMediaCdrom_ReadBuffer,
      TSS_EfiDevicePathMediaCdrom_Trace},z
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_VENDOR,
      "Media Device Path Vendor",
      TSS_EfiDevicePathMediaVendor_ReadBuffer,
      TSS_EfiDevicePathMediaVendor_Trace},
#endif
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_FILE,
      "Media Device Path File",
      TSS_EfiDevicePathMediaFile_ReadBuffer,
      TSS_EfiDevicePathMediaFile_Trace},
#if 0
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_MEDIA,
      "Media Device Path Media",
      TSS_EfiDevicePathMediaMedia_ReadBuffer,
      TSS_EfiDevicePathMediaMedia_Trace},
#endif
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_PIWG_FILE,
      "Media Device Path PIWG File",
      TSS_EfiDevicePathMediaPiwgFile_ReadBuffer,
      TSS_EfiDevicePathMediaPiwgFile_Trace},
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_PIWG_FW,
      "Media Device Path PIWG FW",
      TSS_EfiDevicePathMediaPiwgFw_ReadBuffer,
      TSS_EfiDevicePathMediaPiwgFw_Trace},
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_OFFSET,
      "Media Device Path Offset",
      TSS_EfiDevicePathMediaOffset_ReadBuffer,
      TSS_EfiDevicePathMediaOffset_Trace},
#if 0
     {EFI_DEVICE_PATH_MEDIA_SUBTYPE_RAMDISK,
      "Media Device Path Ramdisk",
      TSS_EfiDevicePathMediaRamdisk_ReadBuffer,
      TSS_EfiDevicePathMediaRamdisk_Trace},
#endif
    };


/* From UEFI 10.3.1 Generic Device Path Structures */

static uint32_t TSS_EfiDevicePathHw_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
					       uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolHwTypeTable) ,
					efiDevicePathProtocolHwTypeTable);
    }
    if (rc == 0) {
	rc = efiDevicePathProtocolHwTypeTable[index].readBufferFunction(uefiDevicePath,
									event, eventSize);
    }
    else {
	/* SubType unknown / unsupported */
	rc = TSS_Array_Unmarshalu(uefiDevicePath->data,
				  uefiDevicePath->protocol.Length -
				  sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL),
				  event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						 uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolAcpiTypeTable) ,
					efiDevicePathProtocolAcpiTypeTable);
    }
    if (rc == 0) {
	rc = efiDevicePathProtocolAcpiTypeTable[index].readBufferFunction(uefiDevicePath,
									  event, eventSize);
    }
    else {
	/* SubType unknown / unsupported */
	rc = TSS_Array_Unmarshalu(uefiDevicePath->data,
				  uefiDevicePath->protocol.Length -
				  sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL),
				  event, eventSize);
    }
    return rc;
}
static uint32_t TSS_EfiDevicePathMsg_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolMsgTypeTable) ,
					efiDevicePathProtocolMsgTypeTable);
    }
    if (rc == 0) {
	rc = efiDevicePathProtocolMsgTypeTable[index].readBufferFunction(uefiDevicePath,
									 event, eventSize);
    }
    else {
	/* SubType unknown / unsupported */
	rc = TSS_Array_Unmarshalu(uefiDevicePath->data,
				  uefiDevicePath->protocol.Length -
				  sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL),
				  event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMedia_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolMediaTypeTable) ,
					efiDevicePathProtocolMediaTypeTable);
    }
    if (rc == 0) {
	rc = efiDevicePathProtocolMediaTypeTable[index].readBufferFunction(uefiDevicePath,
									   event, eventSize);
    }
    else {
	/* SubType unknown / unsupported */
	rc = TSS_Array_Unmarshalu(uefiDevicePath->data,
				  uefiDevicePath->protocol.Length -
				  sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL),
				  event, eventSize);
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathBios_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						 uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    return rc;
}
#endif

static uint32_t TSS_EfiDevicePathEnd_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    /* End has no data */
    uefiDevicePath = uefiDevicePath;
    event = event;
    eventSize = eventSize;
    return rc;
}

static void TSS_EfiDevicePathHw_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolHwTypeTable) ,
					efiDevicePathProtocolHwTypeTable);
    }
    if (rc == 0) {
	efiDevicePathProtocolHwTypeTable[index].traceFunction(uefiDevicePath);
    }
    else {
	printf("Type %02x SubType %02x HW trace not implemented\n",
	       uefiDevicePath->protocol.Type,
	       uefiDevicePath->protocol.SubType);
    }
    return;
}

static void TSS_EfiDevicePathAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolAcpiTypeTable) ,
					efiDevicePathProtocolAcpiTypeTable);
    }
    if (rc == 0) {
	efiDevicePathProtocolAcpiTypeTable[index].traceFunction(uefiDevicePath);
    }
    else {
	printf("Type %02x SubType %02x ACPI trace not implemented\n",
	       uefiDevicePath->protocol.Type,
	       uefiDevicePath->protocol.SubType);
    }
    return;
}
static void TSS_EfiDevicePathMsg_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolMsgTypeTable) ,
					efiDevicePathProtocolMsgTypeTable);
    }
    if (rc == 0) {
	efiDevicePathProtocolMsgTypeTable[index].traceFunction(uefiDevicePath);
    }
    else {
	printf("Type %02x SubType %02x Message trace not implemented\n",
	       uefiDevicePath->protocol.Type,
	       uefiDevicePath->protocol.SubType);
    }
    return;
}

static void TSS_EfiDevicePathMedia_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t rc = 0;
    size_t index;

    if (rc == 0) {
	rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.SubType,
					sizeof(efiDevicePathProtocolMediaTypeTable) ,
					efiDevicePathProtocolMediaTypeTable);
    }
    if (rc == 0) {
	efiDevicePathProtocolMediaTypeTable[index].traceFunction(uefiDevicePath);
    }
    else {
	printf("Type %02x SubType %02x Media trace not implemented\n",
	       uefiDevicePath->protocol.Type,
	       uefiDevicePath->protocol.SubType);
    }
    return;
}

#if 0
static void TSS_EfiDevicePathBios_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x BIOS trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

static void TSS_EfiDevicePathEnd_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    if (uefiDevicePath->protocol.SubType == 0xff) {
	printf("    SubType %02x End Entire Device Path\n", uefiDevicePath->protocol.SubType);
    }
    else if (uefiDevicePath->protocol.SubType == 0x01) {
	printf("    SubType %02x End This Device Path\n", uefiDevicePath->protocol.SubType);
    }
    else {
	printf("    SubType %02x\n", uefiDevicePath->protocol.SubType);
    }
    return;
}

/* From UEFI 10.3.2 Hardware Device Path - Type 1 SubTypes */

static uint32_t TSS_EfiDevicePathHwPCI_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_HW0101 *hw0101 = &uefiDevicePath->hw0101;

    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&hw0101->Function, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&hw0101->Device, event, eventSize);
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathHwPCCARD_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						     uint8_t **event, uint32_t *eventSize)
{
}
static uint32_t TSS_EfiDevicePathHwMMAP_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize)
{
}
#endif

static uint32_t TSS_EfiDevicePathHwVENDOR_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						     uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_HW0104 *hw0104 = &uefiDevicePath->hw0104;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(hw0104->Vendor_GUID,
				  sizeof(hw0104->Vendor_GUID),
				  event, eventSize);
    }
    /* if there is a URI */
    if (uefiDevicePath->protocol.Length >
	(sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL) + sizeof(hw0104->Vendor_GUID))) {

	uefiDevicePath->unionBufferLength = uefiDevicePath->protocol.Length -
					    sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL) -
					    sizeof(hw0104->Vendor_GUID);
	if (rc == 0) {
	    uefiDevicePath->unionBuffer =
		malloc(uefiDevicePath->unionBufferLength);
	    if (uefiDevicePath->unionBuffer == NULL) {
		printf("TSS_EfiDevicePathHwVENDOR_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->unionBufferLength));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->unionBuffer,
				      uefiDevicePath->unionBufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathHwCTRLR_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
}
static uint32_t TSS_EfiDevicePathHwBMC_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						  uint8_t **event, uint32_t *eventSize)
{
}
#endif

static void TSS_EfiDevicePathHwPCI_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_HW0101 *hw0101 = &uefiDevicePath->hw0101;

    printf("    SubType %02x PCI\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Function %02x\n",  hw0101->Function);
    printf("      Device %02x\n",  hw0101->Device);
    return;
}

#if 0
static void TSS_EfiDevicePathHwPCCARD_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}

static void TSS_EfiDevicePathhHwMMAP_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x Hw MMAP trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

static void TSS_EfiDevicePathHwVENDOR_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_HW0104 *hw0104 = &uefiDevicePath->hw0104;
    int isUCS2;

    printf("    SubType %02x Vendor\n",
	   uefiDevicePath->protocol.SubType);
    guid_printf("    Vendor GUID", hw0104->Vendor_GUID);
    /* some Vendor data appears to be UCS-2 NUL terminated */
    if (uefiDevicePath->unionBufferLength > 0) {
	isUCS2String(&isUCS2, uefiDevicePath->unionBuffer, uefiDevicePath->unionBufferLength);
	if (isUCS2) {
	    ucs2_printf("    Vendor: ", uefiDevicePath->unionBuffer,
			(uefiDevicePath->unionBufferLength -2));
	}
	else {
	    TSS_PrintAll("     Vendor",
			 uefiDevicePath->unionBuffer,
			 uefiDevicePath->unionBufferLength);
	}
    }
    return;
}

#if 0
static void TSS_EfiDevicePathHwCTRLR_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x Hw CTRLR trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
static void TSS_EfiDevicePathHwBMC_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x Hw BMC trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

/* From UEFI 10.3.3 ACPI Device Path  - Type 2 SubTypes */

static uint32_t TSS_EfiDevicePathAcpiSubAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_ACPI0201 *acpi0201 = &uefiDevicePath->acpi0201;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&acpi0201->HID, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&acpi0201->UID, event, eventSize);
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathAcpiExpAcpi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
}

static uint32_t TSS_EfiDevicePathAcpiAdr_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
}

static uint32_t TSS_EfiDevicePathAcpiNvdimm_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize)
{
}
#endif

static void TSS_EfiDevicePathAcpiSubAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_ACPI0201 *acpi0201 = &uefiDevicePath->acpi0201;

    printf("    SubType %02x ACPI Device Path\n",
	   uefiDevicePath->protocol.SubType);
    printf("      HID %08x\n",  acpi0201->HID);
    printf("      UID %08x\n",  acpi0201->UID);
    return;
}

#if 0
static void TSS_EfiDevicePathAcpiExpAcpi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}

static void TSS_EfiDevicePathAcpiAdr_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}

static void TSS_EfiDevicePathAcpiNvdimm_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

/* From UEFI 10.3.4 Messaging Device Path - Type 3 SubTypes */

static uint32_t TSS_EfiDevicePathMsgScsi_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG0302 *msg0302 = &uefiDevicePath->msg0302;

    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg0302->TargetID, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg0302->LogicalUnitNumber, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgUsb_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG0305 *msg0305 = &uefiDevicePath->msg0305;

    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg0305->USBParentPort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg0305->Interface, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgUsbClass_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG030F *msg030f = &uefiDevicePath->msg030f;

    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030f->VendorID, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030f->ProductID, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030f->DeviceClass, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030f->DeviceSubclass, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030f->DeviceProtocol, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgSata_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG0312 *msg0312 = &uefiDevicePath->msg0312;

    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg0312->HBAPortNumber, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg0312->PortMultiplierPort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg0312->LogicalUnitNumber, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgNvme_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG0317 *msg0317 = &uefiDevicePath->msg0317;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&msg0317->NamespaceId, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&msg0317->NamespaceUuid, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgMac_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG030B *msg030b = &uefiDevicePath->msg030b;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030b->Mac, sizeof(msg030b->Mac),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030b->IfType, event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgIpv4_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG030C *msg030c = &uefiDevicePath->msg030c;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030c->LocalIPAddress, sizeof(msg030c->LocalIPAddress),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030c->RemoteIPAddress, sizeof(msg030c->RemoteIPAddress),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030c->LocalPort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030c->RemotePort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030c->Protocol, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030c->StaticIPAddress, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030c->GatewayIPAddress, sizeof(msg030c->GatewayIPAddress),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030c->SubnetMask, sizeof(msg030c->SubnetMask),
				  event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgIpv6_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MSG030D *msg030d = &uefiDevicePath->msg030d;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030d->LocalIPAddress, sizeof(msg030d->LocalIPAddress),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030d->RemoteIPAddress, sizeof(msg030d->RemoteIPAddress),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030d->LocalPort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030d->RemotePort, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&msg030d->Protocol, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030d->IPAddressOrigin, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&msg030d->PrefixLength, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030d->GatewayIPAddress, sizeof(msg030d->GatewayIPAddress),
				  event, eventSize);
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgUri_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						   uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;

    /* if there is a URI */
    if (uefiDevicePath->protocol.Length > sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)) {
	if (rc == 0) {
	    uefiDevicePath->unionBuffer =
		malloc(uefiDevicePath->protocol.Length - sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
	    if (uefiDevicePath->unionBuffer == NULL) {
		printf("TSS_EfiDevicePathMsgUri_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->protocol.Length -
				      sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    uefiDevicePath->unionBufferLength = uefiDevicePath->protocol.Length -
						sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL);
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->unionBuffer,
				      uefiDevicePath->unionBufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMsgVendor_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						      uint8_t **event, uint32_t *eventSize)

{
    uint32_t rc = 0;
    TSS_MSG030A *msg030a = &uefiDevicePath->msg030a;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(msg030a->VendorGUID, sizeof(msg030a->VendorGUID),
				  event, eventSize);
    }
    if (uefiDevicePath->protocol.Length >
	(sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL) + sizeof(msg030a->VendorGUID))) {

	uefiDevicePath->unionBufferLength = uefiDevicePath->protocol.Length -
					    sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL) -
					    sizeof(msg030a->VendorGUID);
	if (rc == 0) {
	    uefiDevicePath->unionBuffer = malloc(uefiDevicePath->unionBufferLength);
	    if (uefiDevicePath->unionBuffer == NULL) {
		printf("TSS_EfiDevicePathMsgVendor_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->unionBufferLength))	;
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->unionBuffer,
				      uefiDevicePath->unionBufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

static void     TSS_EfiDevicePathMsgScsi_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG0302 *msg0302 = &uefiDevicePath->msg0302;

    printf("    SubType %02x SCSI\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Target ID %hu\n", msg0302->TargetID);
    printf("      Logical Unit Number %hu\n", msg0302->LogicalUnitNumber);
    return;
}

static void     TSS_EfiDevicePathMsgUsb_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG0305 *msg0305 = &uefiDevicePath->msg0305;

    printf("    SubType %02x USB\n",
	   uefiDevicePath->protocol.SubType);
    printf("      USB Parent Port %u\n", msg0305->USBParentPort);
    printf("      Interface %u\n", msg0305->Interface);
    return;
}

static void     TSS_EfiDevicePathMsgUsbClass_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG030F *msg030f = &uefiDevicePath->msg030f;

    printf("    SubType %02x USB Class\n",
	   uefiDevicePath->protocol.SubType);
    printf("      VendorID %04x\n", msg030f->VendorID);
    printf("      Product ID %04x\n", msg030f->ProductID);
    printf("      Device Class %02x\n", msg030f->DeviceClass);
    printf("      Device Subclass %02x\n", msg030f->DeviceSubclass);
    printf("      Device Protocol %02x\n", msg030f->DeviceProtocol);
    return;
}

static void     TSS_EfiDevicePathMsgNvme_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG0317 *msg0317 = &uefiDevicePath->msg0317;

    printf("    SubType %02x NVME\n",
	   uefiDevicePath->protocol.SubType);
    printf("      NamespaceId %08x\n",  msg0317->NamespaceId);
    printf("      NamespaceUuid %016" PRIx64 "\n", msg0317->NamespaceUuid);
    return;
}

static void     TSS_EfiDevicePathMsgSata_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG0312 *msg0312 = &uefiDevicePath->msg0312;

    printf("    SubType %02x Sata\n",
	   uefiDevicePath->protocol.SubType);
    printf("      HBA Port Number %hu\n", msg0312->HBAPortNumber);
    printf("      Port Multiplier Port %hu\n", msg0312->PortMultiplierPort);
    printf("      Logical Unit Number %hu\n", msg0312->LogicalUnitNumber);
    return;
}

static void 	TSS_EfiDevicePathMsgMac_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG030B *msg030b = &uefiDevicePath->msg030b;

    printf("    SubType %02x MAC\n",
	   uefiDevicePath->protocol.SubType);
    printf("      MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
	   msg030b->Mac[0], msg030b->Mac[1], msg030b->Mac[2],
	   msg030b->Mac[3], msg030b->Mac[4], msg030b->Mac[5]);
    printf("      IF Type %u\n", msg030b->IfType);
    return;
}

static void     TSS_EfiDevicePathMsgIpv4_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG030C *msg030c = &uefiDevicePath->msg030c;

    printf("    SubType %02x Ipv4\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Local IP Address %u.%u.%u.%u\n",
	   msg030c->LocalIPAddress[0], msg030c->LocalIPAddress[1],
	   msg030c->LocalIPAddress[2], msg030c->LocalIPAddress[3]);
    printf("      Remote IP Address %u.%u.%u.%u\n",
	   msg030c->RemoteIPAddress[0], msg030c->RemoteIPAddress[1],
	   msg030c->RemoteIPAddress[2], msg030c->RemoteIPAddress[3]);
    printf("      Local Port %hu\n", msg030c->LocalPort);
    printf("      Remote Port %hu\n", msg030c->RemotePort);
    printf("      Protocol %hu\n", msg030c->Protocol);
    printf("      Static IP Address (bool) %u\n", msg030c->StaticIPAddress);
    printf("      Local IP Address %u.%u.%u.%u\n",
	   msg030c->GatewayIPAddress[0], msg030c->GatewayIPAddress[1],
	   msg030c->GatewayIPAddress[2], msg030c->GatewayIPAddress[3]);
    printf("      Subnet Mask %u.%u.%u.%u\n",
	   msg030c->SubnetMask[0], msg030c->SubnetMask[1],
	   msg030c->SubnetMask[2], msg030c->SubnetMask[3]);
    return;
}

/* TSS_EfiDevicePathMsgIpv6_Trace() does not trace in https://tools.ietf.org/html/rfc5952 format */

static void     TSS_EfiDevicePathMsgIpv6_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG030D *msg030d = &uefiDevicePath->msg030d;

    printf("    SubType %02x Ipv6\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Local IP Address "
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
	   "\n",
	   msg030d->LocalIPAddress[ 0], msg030d->LocalIPAddress[ 1],
	   msg030d->LocalIPAddress[ 2], msg030d->LocalIPAddress[ 3],
	   msg030d->LocalIPAddress[ 4], msg030d->LocalIPAddress[ 5],
	   msg030d->LocalIPAddress[ 6], msg030d->LocalIPAddress[ 7],
	   msg030d->LocalIPAddress[ 8], msg030d->LocalIPAddress[ 9],
	   msg030d->LocalIPAddress[10], msg030d->LocalIPAddress[11],
	   msg030d->LocalIPAddress[12], msg030d->LocalIPAddress[13],
	   msg030d->LocalIPAddress[14], msg030d->LocalIPAddress[15]);
    printf("      Remote IP Address "
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
	   "\n",
	   msg030d->RemoteIPAddress[ 0], msg030d->RemoteIPAddress[ 1],
	   msg030d->RemoteIPAddress[ 2], msg030d->RemoteIPAddress[ 3],
	   msg030d->RemoteIPAddress[ 4], msg030d->RemoteIPAddress[ 5],
	   msg030d->RemoteIPAddress[ 6], msg030d->RemoteIPAddress[ 7],
	   msg030d->RemoteIPAddress[ 8], msg030d->RemoteIPAddress[ 9],
	   msg030d->RemoteIPAddress[10], msg030d->RemoteIPAddress[11],
	   msg030d->RemoteIPAddress[12], msg030d->RemoteIPAddress[13],
	   msg030d->RemoteIPAddress[14], msg030d->RemoteIPAddress[15]);
    printf("      Local Port %hu\n", msg030d->LocalPort);
    printf("      Remote Port %hu\n", msg030d->RemotePort);
    printf("      Protocol %hu\n", msg030d->Protocol);
    printf("      IP Address Origin %u\n", msg030d->IPAddressOrigin);
    printf("      Prefix Length %u\n", msg030d->PrefixLength);
    printf("      Gateway IP Address "
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
	   "\n",
	   msg030d->GatewayIPAddress[ 0], msg030d->GatewayIPAddress[ 1],
	   msg030d->GatewayIPAddress[ 2], msg030d->GatewayIPAddress[ 3],
	   msg030d->GatewayIPAddress[ 4], msg030d->GatewayIPAddress[ 5],
	   msg030d->GatewayIPAddress[ 6], msg030d->GatewayIPAddress[ 7],
	   msg030d->GatewayIPAddress[ 8], msg030d->GatewayIPAddress[ 9],
	   msg030d->GatewayIPAddress[10], msg030d->GatewayIPAddress[11],
	   msg030d->GatewayIPAddress[12], msg030d->GatewayIPAddress[13],
	   msg030d->GatewayIPAddress[14], msg030d->GatewayIPAddress[15]);
    return;
}

static void     TSS_EfiDevicePathMsgUri_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("    SubType %02x URI\n",
	   uefiDevicePath->protocol.SubType);
    printf("      URI: %.*s\n",
	   (int)uefiDevicePath->unionBufferLength,
	   uefiDevicePath->unionBuffer);
}

static void     TSS_EfiDevicePathMsgVendor_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MSG030A *msg030a = &uefiDevicePath->msg030a;

    printf("    SubType %02x Vendor\n",
	   uefiDevicePath->protocol.SubType);
    guid_printf("    Vendor GUID", msg030a->VendorGUID);
    TSS_PrintAll("     Vendor",
		 uefiDevicePath->unionBuffer,
		 uefiDevicePath->unionBufferLength);
    return;
}

/* From UEFI 10.3.3 Media Device Path - Type 4 SubTypes */

static uint32_t TSS_EfiDevicePathMediaHd_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						    uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MEDIA0401 *media0401 = &uefiDevicePath->media0401;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&media0401->PartitionNumber, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&media0401->PartitionStart, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&media0401->PartitionSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(media0401->PartitionSignature,
				  sizeof(media0401->PartitionSignature),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&media0401->PartitionFormat, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&media0401->SignatureType, event, eventSize);
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathMediaCdrom_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize)
{
}

static uint32_t TSS_EfiDevicePathMediaVendor_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize)
{
}
#endif

static uint32_t TSS_EfiDevicePathMediaFile_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						      uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;

    /* if there is a path.  Zero should be an error because of the NUL termination */
    if (uefiDevicePath->protocol.Length > sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)) {
	if (rc == 0) {
	    uefiDevicePath->buffer =
		malloc(uefiDevicePath->protocol.Length - sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
	    if (uefiDevicePath->buffer == NULL) {
		printf("TSS_EfiDevicePathMediaFile_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->protocol.Length -
				      sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    uefiDevicePath->bufferLength = uefiDevicePath->protocol.Length -
					   sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL);
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->buffer,
				      uefiDevicePath->bufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathMediaMedia_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
						       uint8_t **event, uint32_t *eventSize)
{
}
#endif

/* Contents are defined in the UEFI PI Specification, seems to be a GUID. */

static uint32_t TSS_EfiDevicePathMediaPiwgFile_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							  uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;

    if (uefiDevicePath->protocol.Length > sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)) {
	if (rc == 0) {
	    uefiDevicePath->buffer =
		malloc(uefiDevicePath->protocol.Length - sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
	    if (uefiDevicePath->buffer == NULL) {
		printf("TSS_EfiDevicePathMediaPiwgFile_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->protocol.Length -
				      sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    uefiDevicePath->bufferLength = uefiDevicePath->protocol.Length -
					   sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL);
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->buffer,
				      uefiDevicePath->bufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMediaPiwgFw_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;

    /* if there is a path.  Zero should be an error because of the NUL termination */
    if (uefiDevicePath->protocol.Length > sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)) {
	if (rc == 0) {
	    uefiDevicePath->buffer =
		malloc(uefiDevicePath->protocol.Length - sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
	    if (uefiDevicePath->buffer == NULL) {
		printf("TSS_EfiDevicePathMediaPiwgFw_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->protocol.Length -
				      sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    uefiDevicePath->bufferLength = uefiDevicePath->protocol.Length -
					   sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL);
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->buffer,
				      uefiDevicePath->bufferLength,
				      event, eventSize);
	}
    }
    return rc;
}

static uint32_t TSS_EfiDevicePathMediaOffset_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_MEDIA0408 *media0408 = &uefiDevicePath->media0408;

    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&media0408->Reserved, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&media0408->StartingOffset, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&media0408->EndingOffset, event, eventSize);
    }
    return rc;
}

#if 0
static uint32_t TSS_EfiDevicePathMediaRamdisk_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
							 uint8_t **event, uint32_t *eventSize)
{
}
#endif

static void TSS_EfiDevicePathMediaHd_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MEDIA0401 *media0401 = &uefiDevicePath->media0401;

    printf("    SubType %02x Media HD\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Partition Number %u\n",  media0401->PartitionNumber);
    printf("      Partition Start %016" PRIx64 "\n", media0401->PartitionStart);
    printf("      Partition Size %016" PRIx64 "\n", media0401->PartitionSize);
    if (media0401->PartitionFormat == 0x01) {
	printf("      Partition Format PC AT MBR\n");
    }
    else if (media0401->PartitionFormat == 0x02) {
	printf("      Partition Format GUID Partition Table\n");
    }
    else {
	printf("      Partition Format %u unknown\n", media0401->PartitionFormat);
    }
    printf("      Signature Type %u\n", media0401->SignatureType);
    if (media0401->SignatureType == 0x00) {
	printf("      No Disk Signature\n");
    }
    else if (media0401->SignatureType == 0x02) {
	guid_printf("    Signature", media0401->PartitionSignature);
    }
    else {
	TSS_PrintAll("    Signature",
		     media0401->PartitionSignature,
		     sizeof(media0401->PartitionSignature));
    }
    return;
}

#if 0
static void TSS_EfiDevicePathMediaCdrom_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}

static void TSS_EfiDevicePathMediaVendor_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

static void TSS_EfiDevicePathMediaFile_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    /* subtract 2 because this field is NUL terminated */
    printf("    SubType %02x File Path\n",
	   uefiDevicePath->protocol.SubType);
    ucs2_printf("    Path Name: ", uefiDevicePath->buffer,
		(uefiDevicePath->bufferLength -2));
    return;
}

#if 0
static void TSS_EfiDevicePathMediaMedia_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

static void TSS_EfiDevicePathMediaPiwgFile_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("    SubType %02x Firmware File\n",
	   uefiDevicePath->protocol.SubType);
    /* apparently, this value is a GUID */
    if (uefiDevicePath->bufferLength == TSS_EFI_GUID_SIZE) {
	guid_printf("    Firmware File", uefiDevicePath->buffer);
    }
    else {
	TSS_PrintAll("    Firmware File",
		     uefiDevicePath->buffer,
		     uefiDevicePath->bufferLength);
    }
    return;
}

static void TSS_EfiDevicePathMediaPiwgFw_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("    SubType %02x Firmware Volume\n",
	   uefiDevicePath->protocol.SubType);
    /* apparently, this value is a GUID */
    if (uefiDevicePath->bufferLength == TSS_EFI_GUID_SIZE) {
	guid_printf("    Firmware Volume", uefiDevicePath->buffer);
    }
    else {
	TSS_PrintAll("    Firmware Volume",
		     uefiDevicePath->buffer,
		     uefiDevicePath->bufferLength);
    }
    return;
}

static void TSS_EfiDevicePathMediaOffset_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    TSS_MEDIA0408 *media0408 = &uefiDevicePath->media0408;

    printf("    SubType %02x Media Offset\n",
	   uefiDevicePath->protocol.SubType);
    printf("      Starting Offset %016" PRIx64 "\n", media0408->StartingOffset);
    printf("      Ending Offset %016" PRIx64 "\n", media0408->EndingOffset);

    return;
}

#if 0
static void TSS_EfiDevicePathMediaRamdisk_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    printf("Type %02x SubType %02x trace not implemented\n",
	   uefiDevicePath->protocol.Type,
	   uefiDevicePath->protocol.SubType);
    return;
}
#endif

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

static uint32_t TSS_EfiPlatformFirmwareBlob_ReadBuffer(TSST_EFIData *efiData,
						       uint8_t *event, uint32_t eventSize,
						       uint32_t pcrIndex);
static void     TSS_EfiPlatformFirmwareBlob_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlob_ToJson(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_DRIVER_CONFIG
   EV_EFI_VARIABLE_BOOT
   EV_EFI_VARIABLE_AUTHORITY
*/

static void     TSS_EfiVariableData_Init(TSST_EFIData *efiData);
static void     TSS_EfiVariableData_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableData_ReadBuffer(TSST_EFIData *efiData,
					      uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiVariableData_Trace(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void     TSS_EfiVariableDriverConfig_Init(TSST_EFIData *efiData);
static void     TSS_EfiVariableDriverConfig_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableDriverConfig_ReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex);
static void     TSS_EfiVariableDriverConfig_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableDriverConfig_ToJson(TSST_EFIData *efiData);

/* EV_EFI_VARIABLE_BOOT */

static void     TSS_EfiVariableBoot_Init(TSST_EFIData *efiData);
static void     TSS_EfiVariableBoot_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableBoot_ReadBuffer(TSST_EFIData *efiData,
					      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiVariableBoot_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableBoot_ToJson(TSST_EFIData *efiData);

/* for BootOrder */
static void     TSS_EfiVariableBootOrder_Init(TSS_VARIABLE_BOOT_ORDER *variableBootOrder);
static void     TSS_EfiVariableBootOrder_Free(TSS_VARIABLE_BOOT_ORDER *variableBootOrder);
static uint32_t TSS_EfiVariableBootOrder_ReadBuffer(TSS_VARIABLE_BOOT_ORDER *variableBootOrder,
						    uint8_t *VariableData, uint32_t VariableDataLength);
/* for not BootOrder */
static void     TSS_EfiVariableBootPath_Init(TSS_VARIABLE_BOOT *variableBoot);
static void     TSS_EfiVariableBootPath_Free(TSS_VARIABLE_BOOT *variableBoot);
static uint32_t TSS_EfiVariableBootPath_ReadBuffer(TSS_VARIABLE_BOOT *variableBoot,
						   void *VariableData, uint64_t VariableDataLength);

/* EV_EFI_PLATFORM_FIRMWARE_BLOB */

static uint32_t TSS_EfiPlatformFirmwareBlob_ReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex);
static void     TSS_EfiPlatformFirmwareBlob_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlob_ToJson(TSST_EFIData *efiData);

/* TSS_EFI_SIGNATURE_LIST within TSS_UEFI_VARIABLE_DATA */

static void     TSS_EfiSignatureList_Init(TSS_EFI_SIGNATURE_LIST *signatureList);
static void     TSS_EfiSignatureList_Free(TSS_EFI_SIGNATURE_LIST *signatureList);
static uint32_t TSS_EfiSignatureList_ReadBuffer(TSS_EFI_SIGNATURE_LIST *signatureList,
						uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiSignatureList_Trace(TSS_EFI_SIGNATURE_LIST *signatureList);

/* TSS_UEFI_VARIABLE_DATA for PK, KEK, db, dbx, dbr, dbt, etc. */

static uint32_t TSS_EfiSignatureAllLists_ReadBuffer(TSS_EFI_SIGNATURE_LIST **signatureList,
						    uint32_t *signatureListCount,
						    uint8_t *VariableData,
						    uint32_t VariableDataLength);

/* EV_EFI_VARIABLE_AUTHORITY */

static void     TSS_EfiVariableAuthority_Init(TSST_EFIData *efiData);
static void     TSS_EfiVariableAuthority_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableAuthority_ReadBuffer(TSST_EFIData *efiData,
						   uint8_t *event, uint32_t eventSize,
						   uint32_t pcrIndex);
static void     TSS_EfiVariableAuthority_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiVariableAuthority_ToJson(TSST_EFIData *efiData);

/* EV_EFI_BOOT_SERVICES_APPLICATION
   EV_EFI_BOOT_SERVICES_DRIVER
*/

static void     TSS_EfiBootServices_Init(TSST_EFIData *efiData);
static void     TSS_EfiBootServices_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiBootServices_ReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiBootServices_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiBootServices_ToJson(TSST_EFIData *efiData);

/* TSS_UEFI_DEVICE_PATH  */

static void     TSS_UefiDevicePath_Init(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static void     TSS_UefiDevicePath_Free(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static uint32_t TSS_UefiDevicePath_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
					     uint8_t **event, uint32_t *eventSize);
static void     TSS_UefiDevicePath_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath);
static uint32_t TSS_UefiDevicePath_ToJson(TSS_UEFI_DEVICE_PATH *uefiDevicePath);

/* EV_EFI_GPT_EVENT */

static void     TSS_EfiGptEvent_Init(TSST_EFIData *efiData);
static void     TSS_EfiGptEvent_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiGptEvent_ReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiGptEvent_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiGptEvent_ToJson(TSST_EFIData *efiData);

/* EV_EFI_GPT_EVENT */

static uint32_t TSS_EfiPartitionHeader_ReadBuffer(TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader,
						  uint8_t **event, uint32_t *eventSize);
static uint32_t TSS_EfiPartitionEntry_ReadBuffer(TSS_UEFI_PARTITION_ENTRY *entry,
						 uint8_t **event, uint32_t *eventSize);
static void     TSS_EfiPartitionHeader_Trace(TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader);
static void     TSS_EfiPartitionEntry_Trace(TSS_UEFI_PARTITION_ENTRY *entry);

/* EV_POST_CODE */

static void     TSS_EfiPostCode_Init(TSST_EFIData *efiData);
static void     TSS_EfiPostCode_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiPostCode_ReadBuffer(TSST_EFIData *efiData,
					   uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiPostCode_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPostCode_ToJson(TSST_EFIData *efiData);

/* EV_S_CRTM_VERSION
   EV_COMPACT_HASH
*/

static void     TSS_Efi4bBuffer_Init(TSST_EFIData *efiData);
static void     TSS_Efi4bBuffer_Free(TSST_EFIData *efiData);
static uint32_t TSS_Efi4bBuffer_ReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);

/* EV_COMPACT_HASH */

static void     TSS_EfiCompactHash_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCompactHash_ToJson(TSST_EFIData *efiData);

/* EV_IPL */

static void     TSS_EfiIpl_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiIpl_ToJson(TSST_EFIData *efiData);

/* EV_IPL_PARTITION_DATA */

static void     TSS_EfiIplPartitionData_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiIplPartitionData_ToJson(TSST_EFIData *efiData);

/* EV_S_CRTM_VERSION */

static void     TSS_EfiCrtmVersion_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCrtmVersion_ToJson(TSST_EFIData *efiData);

/* EV_S_CRTM_CONTENTS */

static void     TSS_EfiCrtmContents_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiCrtmContents_ToJson(TSST_EFIData *efiData);

/* EV_EFI_ACTION */

static void     TSS_EfiEfiAction_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiEfiAction_ToJson(TSST_EFIData *efiData);

/* Event that is only a printable string */

#if 0
static uint32_t TSS_EfiChar_ReadBuffer(TSST_EFIData *efiData,
				      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex);
static void     TSS_EfiChar_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiChar_ToJson(TSST_EFIData *efiData);

#endif

/* EV_NO_ACTION */

static void     TSS_EvNoAction_Trace(TSST_EFIData *efiData);

/* EV_SEPARATOR */

static void     TSS_EfiSeparator_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiSeparator_ToJson(TSST_EFIData *efiData);

/* EV_ACTION */

static void     TSS_EfiAction_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiAction_ToJson(TSST_EFIData *efiData);

/* EV_EVENT_TAG */

static void     TSS_EfiEventTag_Init(TSST_EFIData *efiData);
static void     TSS_EfiEventTag_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiEvent_ReadBuffer(TSST_EFIData *efiData,
				       uint8_t *event, uint32_t eventSize,
				       uint32_t pcrIndex);
static void     TSS_EfiEventTag_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiEventTag_ToJson(TSST_EFIData *efiData);

/* EV_EFI_HANDOFF_TABLES
   EV_EFI_HANDOFF_TABLES2
   EV_TABLE_OF_DEVICES
*/

static void     TSS_EfiHandoffTables_Init(TSST_EFIData *efiData);
static void     TSS_EfiHandoffTables_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTables_ReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize,
					       uint32_t pcrIndex);
static void     TSS_EfiHandoffTables_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTables_ToJson(TSST_EFIData *efiData);

static void     TSS_EfiHandoffTables2_Init(TSST_EFIData *efiData);
static void     TSS_EfiHandoffTables2_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTables2_ReadBuffer(TSST_EFIData *efiData,
						uint8_t *event, uint32_t eventSize,
						uint32_t pcrIndex);
static void     TSS_EfiHandoffTables2_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiHandoffTables2_ToJson(TSST_EFIData *efiData);

/* common code */

static uint32_t
TSS_EfiTablePointers_ReadBuffer(TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers,
				uint8_t **event, uint32_t *eventSize,
				uint32_t pcrIndex);


/* EV_EFI_PLATFORM_FIRMWARE_BLOB2 */

static void     TSS_EfiPlatformFirmwareBlob2_Init(TSST_EFIData *efiData);
static void     TSS_EfiPlatformFirmwareBlob2_Free(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlob2_ReadBuffer(TSST_EFIData *efiData,
						       uint8_t *event, uint32_t eventSize,
						       uint32_t pcrIndex);
static void     TSS_EfiPlatformFirmwareBlob2_Trace(TSST_EFIData *efiData);
static uint32_t TSS_EfiPlatformFirmwareBlob2_ToJson(TSST_EFIData *efiData);

/* Table to map eventType to handling function callbacks.

   Missing events return an TSS_RC_NOT_IMPLEMENTED.

   Events with NULL for initFunction and freeFunction are legal, meaning that the readBufferFunction
   will not malloc memory that needs pointers to be initialized to NULL and freed,

   NULL entries for readBufferFunction, traceFunction, or toJsonFunction are errors.
*/

/* function prototypes for event callback table */

typedef void     (*TSS_EFIData_Init_Function_t)(TSST_EFIData *efiData);
typedef void     (*TSS_EFIData_Free_Function_t)(TSST_EFIData *efiData);
typedef uint32_t (*TSS_EFIData_ReadBuffer_Function_t)(TSST_EFIData *efiData,
						      uint8_t *event,
						      uint32_t eventSize,
						      uint32_t pcrIndex);
typedef void     (*TSS_EFIData_Trace_Function_t)(TSST_EFIData *efiData);
typedef uint32_t (*TSS_EFIData_ToJson_Function_t)(TSST_EFIData *efiData);

typedef struct {
    uint32_t eventType;					/* PC Client event */
    TSS_EFIData_Init_Function_t		initFunction;
    TSS_EFIData_Free_Function_t		freeFunction;
    TSS_EFIData_ReadBuffer_Function_t	readBufferFunction;
    TSS_EFIData_Trace_Function_t	traceFunction;
    TSS_EFIData_ToJson_Function_t	toJsonFunction;
} EFI_EVENT_TYPE_TABLE;

const EFI_EVENT_TYPE_TABLE efiEventTypeTable [] =
    {
#if 0	/* reserved for future use */
     {EV_PREBOOT_CERT,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
#endif
     {EV_POST_CODE,
      TSS_EfiPostCode_Init,
      TSS_EfiPostCode_Free,
      TSS_EfiPostCode_ReadBuffer,
      TSS_EfiPostCode_Trace,
      TSS_EfiPostCode_ToJson},
#if 0	/* deprecated */
     {EV_UNUSED,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
#endif
     {EV_NO_ACTION,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EvNoAction_Trace,
      NULL},
     {EV_SEPARATOR,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiSeparator_Trace,
      TSS_EfiSeparator_ToJson},
     {EV_ACTION,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiAction_Trace,
      TSS_EfiAction_ToJson},
     {EV_EVENT_TAG,
      TSS_EfiEventTag_Init,
      TSS_EfiEventTag_Free,
      TSS_EfiEvent_ReadBuffer,
      TSS_EfiEventTag_Trace,
      TSS_EfiEventTag_ToJson},
     {EV_S_CRTM_CONTENTS,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiCrtmContents_Trace,
      TSS_EfiCrtmContents_ToJson},
     {EV_S_CRTM_VERSION,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiCrtmVersion_Trace,
      TSS_EfiCrtmVersion_ToJson},
#if 0	/* needs a test event log */
     {EV_CPU_MICROCODE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_PLATFORM_CONFIG_FLAGS,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
#endif
     {EV_TABLE_OF_DEVICES,
      TSS_EfiHandoffTables_Init,
      TSS_EfiHandoffTables_Free,
      TSS_EfiHandoffTables_ReadBuffer,
      TSS_EfiHandoffTables_Trace,
      TSS_EfiHandoffTables_ToJson},
     {EV_COMPACT_HASH,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiCompactHash_Trace,
      TSS_EfiCompactHash_ToJson},
     {EV_IPL,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiIpl_Trace,
      TSS_EfiIpl_ToJson},
     {EV_IPL_PARTITION_DATA,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiIplPartitionData_Trace,
      TSS_EfiIplPartitionData_ToJson},
#if 0	/* needs a test event log */
     {EV_NONHOST_CODE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NONHOST_CONFIG,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_NONHOST_INFO,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_OMIT_BOOT_DEVICE_EVENTS,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
#endif
    {EV_EFI_VARIABLE_DRIVER_CONFIG,
      TSS_EfiVariableDriverConfig_Init,
      TSS_EfiVariableDriverConfig_Free,
      TSS_EfiVariableDriverConfig_ReadBuffer,
      TSS_EfiVariableDriverConfig_Trace,
      TSS_EfiVariableDriverConfig_ToJson},
     {EV_EFI_VARIABLE_BOOT,
      TSS_EfiVariableBoot_Init,
      TSS_EfiVariableBoot_Free,
      TSS_EfiVariableBoot_ReadBuffer,
      TSS_EfiVariableBoot_Trace,
      TSS_EfiVariableBoot_ToJson},
     {EV_EFI_BOOT_SERVICES_APPLICATION,
      TSS_EfiBootServices_Init,
      TSS_EfiBootServices_Free,
      TSS_EfiBootServices_ReadBuffer,
      TSS_EfiBootServices_Trace,
      TSS_EfiBootServices_ToJson},
     {EV_EFI_BOOT_SERVICES_DRIVER,
      TSS_EfiBootServices_Init,
      TSS_EfiBootServices_Free,
      TSS_EfiBootServices_ReadBuffer,
      TSS_EfiBootServices_Trace,
      TSS_EfiBootServices_ToJson},
#if 0	/* needs a test event log */
     {EV_EFI_RUNTIME_SERVICES_DRIVER,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
#endif
     {EV_EFI_GPT_EVENT,
      TSS_EfiGptEvent_Init,
      TSS_EfiGptEvent_Free,
      TSS_EfiGptEvent_ReadBuffer,
      TSS_EfiGptEvent_Trace,
      TSS_EfiGptEvent_ToJson},
     {EV_EFI_ACTION,
      TSS_Efi4bBuffer_Init,
      TSS_Efi4bBuffer_Free,
      TSS_Efi4bBuffer_ReadBuffer,
      TSS_EfiEfiAction_Trace,
      TSS_EfiEfiAction_ToJson},
     {EV_EFI_PLATFORM_FIRMWARE_BLOB,
      NULL,
      NULL,
      TSS_EfiPlatformFirmwareBlob_ReadBuffer,
      TSS_EfiPlatformFirmwareBlob_Trace,
      TSS_EfiPlatformFirmwareBlob_ToJson},
     {EV_EFI_HANDOFF_TABLES,
      TSS_EfiHandoffTables_Init,
      TSS_EfiHandoffTables_Free,
      TSS_EfiHandoffTables_ReadBuffer,
      TSS_EfiHandoffTables_Trace,
      TSS_EfiHandoffTables_ToJson},
     {EV_EFI_HANDOFF_TABLES2,
      TSS_EfiHandoffTables2_Init,
      TSS_EfiHandoffTables2_Free,
      TSS_EfiHandoffTables2_ReadBuffer,
      TSS_EfiHandoffTables2_Trace,
      TSS_EfiHandoffTables2_ToJson},
     {EV_EFI_PLATFORM_FIRMWARE_BLOB2,
      TSS_EfiPlatformFirmwareBlob2_Init,
      TSS_EfiPlatformFirmwareBlob2_Free,
      TSS_EfiPlatformFirmwareBlob2_ReadBuffer,
      TSS_EfiPlatformFirmwareBlob2_Trace,
      TSS_EfiPlatformFirmwareBlob2_ToJson},
     {EV_EFI_HCRTM_EVENT,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
     {EV_EFI_VARIABLE_AUTHORITY,
      TSS_EfiVariableAuthority_Init,
      TSS_EfiVariableAuthority_Free,
      TSS_EfiVariableAuthority_ReadBuffer,
      TSS_EfiVariableAuthority_Trace,
      TSS_EfiVariableAuthority_ToJson},
     {EV_EFI_SUPERMICRO_1,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL},
    };

static uint32_t TSS_EFI_GetTableIndex(size_t *index, uint32_t eventType);

/* TSS_EFI_GetTableIndex() searches the event type table for the event handlers.

   Returns TSS_RC_NOT_IMPLEMENTED if the event type is unknown.
*/

static uint32_t TSS_EFI_GetTableIndex(size_t *index, uint32_t eventType)
{
    for (*index = 0 ;
	 *index < sizeof(efiEventTypeTable) / sizeof(EFI_EVENT_TYPE_TABLE) ;
	 (*index)++) {
	if (efiEventTypeTable[*index].eventType == eventType) {
	    return 0;	/* match */
	}
    }
    return TSS_RC_NOT_IMPLEMENTED;		/* no match */
}

/*
  This is the library external interface
*/

/* TSS_EFIData_Init() initializes the efiData structure based on the EFI eventType so that
   TSS_EFIData_Free() is safe.

   Returns

   TSS_RC_NOT_IMPLEMENTED: eventType is not supported
   TSS_RC_OUT_OF_MEMORY: malloc failure
*/

uint32_t TSS_EFIData_Init(TSST_EFIData **efiData,	/* freed by TSS_EFIData_Free */
			  uint32_t eventType,
			  const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;
    /* if the eventType is supported */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, eventType);
    }
    /* malloc the structure */
    if (rc == 0) {
	*efiData = malloc(sizeof(TSST_EFIData));	/* freed by caller */
	if (*efiData == NULL) {
	    printf("TSS_EFIData_Init: Error allocating %u bytes\n",
		   (unsigned int)sizeof(TSST_EFIData));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	(*efiData)->eventType = eventType;
	/* if there is an initialization function */
	/* eventType specific initialization */
	if (efiEventTypeTable[index].initFunction != NULL) {
	    efiEventTypeTable[index].initFunction(*efiData);
	}
	/* NULL is not an error, means that no read malloc will occur */
    }
    return rc;
}

/* TSS_EFIData_Free() the efiData structure based on the EFI eventType. */

void TSS_EFIData_Free(TSST_EFIData *efiData,
		      const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    if (efiData != NULL) {
	/* a failure here is a call sequence error */
	if (rc == 0) {
	    rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
	}
	if (rc == 0) {
	    /* eventType specific free */
	    if (efiEventTypeTable[index].freeFunction != NULL) {
		efiEventTypeTable[index].freeFunction(efiData);
	    }
	    /* NULL is not an error, means that no read malloc occured */
	}
	free(efiData);
    }
    return;
}

/* TSS_EFIData_ReadBuffer() parses the event based on the EFI eventType.

   Returns TSS_RC_NOT_IMPLEMENTED if the eventType is not supported.
*/

uint32_t TSS_EFIData_ReadBuffer(TSST_EFIData *efiData,
				uint8_t *event, uint32_t eventSize,
				uint32_t pcrIndex,
				const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    /* save the PCR index because some subsequent functions depend on the PCR value */
    if (rc == 0) {
	efiData->pcrIndex = pcrIndex;
    }
    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
    }
    if (rc == 0) {
	/* eventType specific read buffer */
	if (efiEventTypeTable[index].readBufferFunction != NULL) {
	    rc = efiEventTypeTable[index].readBufferFunction(efiData,
							     event, eventSize,
							     pcrIndex);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    return rc;
}

/* TSS_EFIData_Trace() traces the efiData to stdout.

   It assumes that the TSS_EFIData structure and eventType are valid.
*/

void TSS_EFIData_Trace(TSST_EFIData *efiData,
		       const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
	if (rc != 0) {
	    printf("TSS_EFIData_Trace: eventType %08x is not in trace table\n",
		   efiData->eventType);
	}
    }
    if (rc == 0) {
	/* eventType specific traceFunction */
	if (efiEventTypeTable[index].traceFunction != NULL) {
	    efiEventTypeTable[index].traceFunction (efiData);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    printf("TSS_EFIData_Trace: eventType %08x has NULL trace function\n",
		   efiData->eventType);
	}
    }
    return;
}

/* TSS_EFIData_ToJson() outputs the efiData to stdout as json */

uint32_t TSS_EFIData_ToJson(TSST_EFIData *efiData,
			    const TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t rc = 0;
    size_t index;
    /*for future use, to handle PFP differences */
    specIdEvent = specIdEvent;

    /* a failure here is a call sequence error */
    if (rc == 0) {
	rc = TSS_EFI_GetTableIndex(&index, efiData->eventType);
    }
    if (rc == 0) {
	/* eventType specific toJsonFunction */
	if (efiEventTypeTable[index].toJsonFunction != NULL) {
	    rc = efiEventTypeTable[index].toJsonFunction(efiData);
	}
	/* this should never occur, there should be no NULLs in the table */
	else {
	    rc = TSS_RC_NOT_IMPLEMENTED;
	}
    }
    return rc;
}

/* EV_POST_CODE handlers */

static void     TSS_EfiPostCode_Init(TSST_EFIData *efiData)
{
    TSS_POST_CODE_TAGGED_EVENT *taggedEvent = &efiData->efiData.postTaggedEvent;
    taggedEvent->tag = TSS_EV_POST_CODE_UNKNOWN;
    taggedEvent->unionBufferLength = 0;
    taggedEvent->unionBuffer = NULL;
    return;
}

static void     TSS_EfiPostCode_Free(TSST_EFIData *efiData)
{
    TSS_POST_CODE_TAGGED_EVENT *taggedEvent = &efiData->efiData.postTaggedEvent;
    free(taggedEvent->unionBuffer);
    return;
}

static uint32_t TSS_EfiPostCode_ReadBuffer(TSST_EFIData *efiData,
					   uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_POST_CODE_TAGGED_EVENT *taggedEvent = &efiData->efiData.postTaggedEvent;
    pcrIndex = pcrIndex;

    /* allocate the taggedEventData */
    if (eventSize > 0) {
	if (rc == 0) {
	    taggedEvent->unionBufferLength = eventSize;
	    taggedEvent->unionBuffer = malloc(eventSize);
	    if (taggedEvent->unionBuffer == NULL) {
		printf("TSS_EfiPostCode_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(eventSize))	;
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(taggedEvent->unionBuffer,
				      taggedEvent->unionBufferLength,
				      &event, &eventSize);
	}
	/* guess at the meaning of the event */
	if (rc == 0) {
	    if (taggedEvent->unionBufferLength == sizeof(TSS_UEFI_PLATFORM_FIRMWARE_BLOB)) {

		TSS_UEFI_PLATFORM_FIRMWARE_BLOB *firmwareBlob = &taggedEvent->postCode.firmwareBlob;
		uint8_t *tmpEvent = taggedEvent->unionBuffer;
		uint32_t tmpEventSize = taggedEvent->unionBufferLength;

		taggedEvent->tag = TSS_EV_POST_CODE_BLOB;
		if (rc == 0) {
		    rc = TSS_UINT64LE_Unmarshal(&firmwareBlob->BlobBase, &tmpEvent , &tmpEventSize);
		}
		if (rc == 0) {
		    rc = TSS_UINT64LE_Unmarshal(&firmwareBlob->BlobLength, &tmpEvent , &tmpEventSize);
		}
	    }
	    else if ((taggedEvent->unionBufferLength > sizeof(TSS_UEFI_PLATFORM_FIRMWARE_BLOB) &&
		      taggedEvent->unionBufferLength == ((sizeof(uint8_t) +
							     sizeof(UEFI_PHYSICAL_ADDRESS) +
							     sizeof(uint64_t) +
							  taggedEvent->unionBuffer[0])))) {

		TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *firmwareBlob2 =
		    &taggedEvent->postCode.firmwareBlob2;
		uint8_t *tmpEvent = taggedEvent->unionBuffer;
		uint32_t tmpEventSize = taggedEvent->unionBufferLength;

		taggedEvent->tag = TSS_EV_POST_CODE_BLOB2;
		if (rc == 0) {
		    rc = TSS_UINT8_Unmarshalu(&firmwareBlob2->BlobDescriptionSize,
					      &tmpEvent , &tmpEventSize);
		}
		/* skip the BlobDescription, a variable length buffer in the middle of the
		   structure */
		if (rc == 0) {
		    tmpEvent += taggedEvent->unionBuffer[0];
		    tmpEventSize -= taggedEvent->unionBuffer[0];
		}
		if (rc == 0) {
		    rc = TSS_UINT64LE_Unmarshal(&firmwareBlob2->BlobBase,
						&tmpEvent , &tmpEventSize);
		}
		if (rc == 0) {
		    rc = TSS_UINT64LE_Unmarshal(&firmwareBlob2->BlobLength,
						&tmpEvent , &tmpEventSize);
		}
		/* then copy just the BlobDescription, overwriting the rest of the already
		   unmarshaled event */
		if (rc == 0) {
		    memmove(taggedEvent->unionBuffer,
			    taggedEvent->unionBuffer + sizeof(uint8_t),
			    taggedEvent->unionBuffer[0]);
		}
	    }
	    else {
		int isAscii;
		isAsciiString(&isAscii,
			      taggedEvent->unionBuffer, taggedEvent->unionBufferLength);
		if (isAscii) {
		    taggedEvent->tag = TSS_EV_POST_CODE_ASCII;
		    /* string remains in unionBuffer */
		}
		else {
		    taggedEvent->tag = TSS_EV_POST_CODE_UNKNOWN;
		    /* event remains in unionBuffer */
		}
	    }
	}
    }
    else {
	taggedEvent->tag = TSS_EV_POST_CODE_UNKNOWN;
    }
    return rc;
}

static void     TSS_EfiPostCode_Trace(TSST_EFIData *efiData)
{
    TSS_POST_CODE_TAGGED_EVENT *taggedEvent = &efiData->efiData.postTaggedEvent;

    switch (taggedEvent->tag) {
       case TSS_EV_POST_CODE_BLOB:
	 printf("  BlobBase: %016" PRIx64 "\n", taggedEvent->postCode.firmwareBlob.BlobBase);
	 printf("  BlobLength: %016" PRIx64 "\n", taggedEvent->postCode.firmwareBlob.BlobLength);
	break;
      case TSS_EV_POST_CODE_BLOB2:
	printf("  BlobDescription: %.*s\n", 
	       (int)taggedEvent->postCode.firmwareBlob2.BlobDescriptionSize,
	       taggedEvent->unionBuffer);

	printf("  BlobBase: %016" PRIx64 "\n", taggedEvent->postCode.firmwareBlob2.BlobBase);
	printf("  BlobLength: %016" PRIx64 "\n", taggedEvent->postCode.firmwareBlob2.BlobLength);
	break;
      case TSS_EV_POST_CODE_ASCII:
	printf("  Post Code: %.*s\n",
	       (int)taggedEvent->unionBufferLength,
	       taggedEvent->unionBuffer);
	break;
      case TSS_EV_POST_CODE_UNKNOWN:
      default:
	TSS_PrintAll("   Data:", taggedEvent->unionBuffer, taggedEvent->unionBufferLength);
    }
    return;
}

static uint32_t TSS_EfiPostCode_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_POST_CODE_TAGGED_EVENT *taggedEvent = &efiData->efiData.postTaggedEvent;
    taggedEvent = taggedEvent;
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_PLATFORM_FIRMWARE_BLOB handlers */

static uint32_t TSS_EfiPlatformFirmwareBlob_ReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob->BlobBase, &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob->BlobLength, &event, &eventSize);
    }
    return rc;
}

static void TSS_EfiPlatformFirmwareBlob_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    printf("  BlobBase: %016" PRIx64 "\n", uefiPlatformFirmwareBlob->BlobBase);
    printf("  BlobLength: %016" PRIx64 "\n", uefiPlatformFirmwareBlob->BlobLength);
    return;
}

static uint32_t TSS_EfiPlatformFirmwareBlob_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB *uefiPlatformFirmwareBlob =
	&efiData->efiData.uefiPlatformFirmwareBlob;
    uefiPlatformFirmwareBlob = uefiPlatformFirmwareBlob; /* to silence compiler */
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG handlers */

static void TSS_EfiVariableData_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData->UnicodeName = NULL;
    uefiVariableData->VariableData = NULL;
    uefiVariableData->variableDataTag = TSS_VAR_UNKNOWN;
    return;
}

static void TSS_EfiVariableData_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    free(uefiVariableData->UnicodeName);
    free(uefiVariableData->VariableData);
    return;
}

/* TSS_EfiVariableData_ReadBuffer()

   Common code to several events.

   Validates that the event has sufficient bytes for VariableDataLength
*/

static uint32_t TSS_EfiVariableData_ReadBuffer(TSST_EFIData *efiData,
					      uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(uefiVariableData->VariableName,
				  sizeof(uefiVariableData->VariableName),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiVariableData->UnicodeNameLength,
				    event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiVariableData->VariableDataLength,
				    event, eventSize);
    }
    /* sanity check the lengths since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > EFI_LENGTH_MAX/2) {
	    printf("TSS_EfiVariableData_ReadBuffer: UnicodeNameLength %" PRIu64 " too large\n",
		   uefiVariableData->UnicodeNameLength);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > EFI_LENGTH_MAX) {
	    printf("TSS_EfiVariableData_ReadBuffer: VariableDataLength %" PRIu64 " too large\n",
		   uefiVariableData->VariableDataLength );
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the UnicodeName array, unicode means byte array is length * 2 */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > 0) {
	    /* freed by TSS_EfiVariableData_Free */
	    uefiVariableData->UnicodeName =
		malloc((size_t)(uefiVariableData->UnicodeNameLength) *2);
	    if (uefiVariableData->UnicodeName == NULL) {
		printf("TSS_EfiVariableData_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiVariableData->UnicodeNameLength) *2);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal UnicodeName */
    if (rc == 0) {
	if (uefiVariableData->UnicodeNameLength > 0) {
	    rc = TSS_Array_Unmarshalu(uefiVariableData->UnicodeName,
				      (uint16_t)(uefiVariableData->UnicodeNameLength) *2,
				      event, eventSize);
	}
	else {
	    /* FIXME is UnicodeNameLength zero an error ? */
	}
    }
    /* allocate the VariableData array */
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > 0) {
	    /* freed by TSS_EfiVariableData_Free */
	    uefiVariableData->VariableData =
		malloc((size_t)uefiVariableData->VariableDataLength);
	    if (uefiVariableData->VariableData == NULL) {
		printf("TSS_EfiVariableData_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)uefiVariableData->VariableDataLength);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal VariableData */
    if (rc == 0) {
	if (uefiVariableData->VariableDataLength > 0) {
	    rc = TSS_Array_Unmarshalu(uefiVariableData->VariableData,
				      (uint16_t)uefiVariableData->VariableDataLength,
				      event, eventSize);
	}
	else {
	    /* FIXME is VariableDataLength zero an error ? */
	}
    }
    return rc;
}

/* common TSS_UEFI_VARIABLE_DATA trace */

static void TSS_EfiVariableData_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    guid_printf("Variable GUID", uefiVariableData->VariableName);
    ucs2_printf("Variable: ", uefiVariableData->UnicodeName,
		(uint32_t)uefiVariableData->UnicodeNameLength * 2);
    printf("  VariableDataLength: %" PRIu64 "\n", uefiVariableData->VariableDataLength);
    return;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void TSS_EfiVariableDriverConfig_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_EfiVariableData_Init(efiData);
    uefiVariableData->variableDriverConfig.signatureListCount = 0;
    uefiVariableData->variableDriverConfig.signatureList = NULL;
    return;
}

static void TSS_EfiVariableDriverConfig_Free(TSST_EFIData *efiData)
{
    uint32_t count;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    for (count = 0 ; count < uefiVariableData->variableDriverConfig.signatureListCount ; count++) {
	TSS_EfiSignatureList_Free(uefiVariableData->variableDriverConfig.signatureList + count);
    }
    free(uefiVariableData->variableDriverConfig.signatureList);
    TSS_EfiVariableData_Free(efiData);
    return;
}

static uint32_t TSS_EfiVariableDriverConfig_ReadBuffer(TSST_EFIData *efiData,
						      uint8_t *event, uint32_t eventSize,
						      uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index;
    int enabled;	/* boolean */
    pcrIndex = pcrIndex;

    /* common code for TSS_UEFI_VARIABLE_DATA */
    if (rc == 0) {
	rc = TSS_EfiVariableData_ReadBuffer(efiData, &event, &eventSize);
    }
    /* map from UnicodeName to structure tag */
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    /*
      Specific code for EV_EFI_VARIABLE_DRIVER_CONFIG
    */
    /* VariableDataLength 0 is treated as though its contents were zero.  Even though this
       does not meet the UEFI spec, some platforms do this.  */
    if (rc == 0) {
	if ((uefiVariableData->VariableDataLength == 0) ||
	    ((uefiVariableData->VariableDataLength == 1) &&
	     (uefiVariableData->VariableData[0] == 0))) {
	    enabled = 0;	/* false */
	}
	else {
	    enabled = 1;
	}
    }
    if (rc == 0) {
	switch (uefiVariableData->variableDataTag) {
	  case TSS_VAR_SECUREBOOT:
	  case TSS_VAR_AUDITMODE:
	  case TSS_VAR_DEPLOYEDMODE:
	  case TSS_VAR_SETUPMODE:
	    /* intentional fall through */
	    uefiVariableData->variableDriverConfig.enabled = enabled;
	    break;
	/* unmarshal TSS_EFI_SIGNATURE_LIST's */
	  case TSS_VAR_PK:
	  case TSS_VAR_KEK:
	  case TSS_VAR_DB:
	  case TSS_VAR_DBR:
	  case TSS_VAR_DBT:
	  case TSS_VAR_DBX:
	  case TSS_VAR_MOKLIST:
	  case TSS_VAR_MOKLISTX:
	    /* intentional fall through */
	    rc = TSS_EfiSignatureAllLists_ReadBuffer
		 (&uefiVariableData->variableDriverConfig.signatureList,
		  &uefiVariableData->variableDriverConfig.signatureListCount,
		  uefiVariableData->VariableData,
		  (uint32_t)uefiVariableData->VariableDataLength);
	    /* trace the GUID and Var as errors */
	    if (rc != 0) {
		printf("TSS_EfiVariableDriverConfig_ReadBuffer: "
		       "Error TSS_UEFI_VARIABLE_DATA structure, tag %u\n",
		       uefiVariableData->variableDataTag);
		TSS_EfiVariableData_Trace(efiData);
	    }
	    break;
	  default:
	    /* FIXME unknown Variable Name strings */
	    ;
	}
    }
    return rc;
}

/* TSS_EfiSignatureAllLists_ReadBuffer() reads a VariableData containing zero or more
   signature lists.
*/

static uint32_t TSS_EfiSignatureAllLists_ReadBuffer(TSS_EFI_SIGNATURE_LIST **signatureList,
						    uint32_t *signatureListCount,
						    uint8_t *VariableData,
						    uint32_t VariableDataLength)
{
    uint32_t rc = 0;

    /* parse all the VariableData */
    while ((rc == 0) && (VariableDataLength > 0)) {
	/* malloc an additional *TSS_EFI_SIGNATURE_LIST */
	if (rc == 0) {
	    void *tmpptr;			/* for realloc */

	    /* freed by TSS_EfiVariableData_Free */
	    tmpptr = realloc(*signatureList,
			     sizeof(TSS_EFI_SIGNATURE_LIST) * ((size_t)(*signatureListCount)+1));
	    if (tmpptr != NULL) {
		*signatureList = tmpptr;
		(*signatureListCount)++;
	    }
	    else {
		printf("TSS_EfiSignatureAllLists_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)sizeof(TSS_EFI_SIGNATURE_LIST) * *signatureListCount);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal this TSS_EFI_SIGNATURE_LIST */
	if (rc == 0) {
	    TSS_EFI_SIGNATURE_LIST *nextSignatureList = (*signatureList) + *signatureListCount -1;
	    TSS_EfiSignatureList_Init(nextSignatureList);	/* for safe free */
	    rc = TSS_EfiSignatureList_ReadBuffer(nextSignatureList,
						&VariableData, &VariableDataLength);
	}
    }
    return rc;
}

static void     TSS_EfiSignatureList_Init(TSS_EFI_SIGNATURE_LIST *signatureList)
{
    signatureList->SignatureHeader = NULL;
    signatureList->Signatures = NULL;
    signatureList->signaturesCount = 0;
}

static void     TSS_EfiSignatureList_Free(TSS_EFI_SIGNATURE_LIST *signatureList)
{
    uint32_t count;

    free(signatureList->SignatureHeader);
    /* free all the TSS_EFI_SIGNATURE_DATA */
    for (count = 0 ; count < signatureList->signaturesCount ; count++) {
	free((signatureList->Signatures + count)->SignatureData);
    }
    free(signatureList->Signatures);
    return;
}

/* TSS_EfiSignatureList_ReadBuffer() reads one TSS_EFI_SIGNATURE_LIST from the event VariableData.
   It moves the pointers since there can be more than one TSS_EFI_SIGNATURE_LIST event.
 */

static uint32_t TSS_EfiSignatureList_ReadBuffer(TSS_EFI_SIGNATURE_LIST *signatureList,
						uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    uint32_t signatureDataLength;
    uint32_t tmpSignatureListSize;	/* because cannot change SignatureSize */

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(signatureList->SignatureType,
				  sizeof(signatureList->SignatureType),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureListSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureHeaderSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&signatureList->SignatureSize, event, eventSize);
    }
    /* range check this untrusted value, to prevent a large malloc */
    if (rc == 0) {
	if (signatureList->SignatureSize > *eventSize) {
	    printf("TSS_EfiSignatureList_ReadBuffer: Error in SignatureSize %u\n",
		   (unsigned int)(signatureList->SignatureSize));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* the SignatureSize must have at least the mandatory SignatureOwner GUID */
    if (rc == 0) {
	if (signatureList->SignatureSize >= sizeof(signatureList->Signatures->SignatureOwner)) {
	    signatureDataLength =
		signatureList->SignatureSize - sizeof(signatureList->Signatures->SignatureOwner);
	}
	else {
	    /* malformed TSS_EFI_SIGNATURE_LIST, needs at least GUID SignatureOwner */
	    printf("TSS_EfiSignatureList_ReadBuffer: Error in SignatureSize %u\n",
		   (unsigned int)(signatureList->SignatureSize));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* sanity check that the SignatureListSize is consistent with the SignatureSize.  Each signature
       must be the same length. */
    if (rc == 0) {
	/*  array of TSS_EFI_SIGNATURE_DATA is SignatureListSize minus header */
	tmpSignatureListSize = signatureList->SignatureListSize -
			       sizeof(signatureList->SignatureType)
			       - (sizeof(uint32_t) * 3);
	if ((tmpSignatureListSize % signatureList->SignatureSize) != 0) {
	    /* malformed TSS_EFI_SIGNATURE_LIST */
	    printf("TSS_EfiSignatureList_ReadBuffer: Error in SignatureSize %u\n",
		   (unsigned int)(signatureList->SignatureSize));
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }

    /* FIXME handle SignatureHeaderSize, if not zero, this breaks, based on SignatureType GUID */

    /* consume this TSS_EFI_SIGNATURE_LIST */
    for ( ; (rc == 0) && (tmpSignatureListSize > 0) ;
	  tmpSignatureListSize-= signatureList->SignatureSize) {

	TSS_EFI_SIGNATURE_DATA *nextSignatureData;
	/* malloc an additional TSS_EFI_SIGNATURE_DATA */
	if (rc == 0) {
	    void *tmpptr;			/* for realloc */

	    /* track the number of TSS_EFI_SIGNATURE_DATA in the TSS_EFI_SIGNATURE_LIST */
	    /* expand the array */
	    /* freed by TSS_EfiSignatureList_Free */
	    tmpptr = realloc(signatureList->Signatures,
			     sizeof(TSS_EFI_SIGNATURE_DATA) * ((size_t)(signatureList->signaturesCount)+1));
	    if (tmpptr != NULL) {
		signatureList->Signatures = tmpptr;
		(signatureList->signaturesCount)++;
		/* point to next TSS_EFI_SIGNATURE_DATA in array */
		nextSignatureData = signatureList->Signatures + signatureList->signaturesCount-1;
		nextSignatureData->SignatureData = NULL;	/* for free */
	    }
	    else {
		printf("TSS_EfiSignatureList_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(sizeof(TSS_EFI_SIGNATURE_DATA) *
				      signatureList->signaturesCount));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal the signature owner */
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(nextSignatureData->SignatureOwner,
				      sizeof(signatureList->SignatureType),
				      event, eventSize);
	}
	/* malloc an TSS_EFI_SIGNATURE_DATA SignatureData */
	if (rc == 0) {
	    void *tmpptr;			/* for realloc */
	    /* SignatureData is SignatureSize less the GUID SignatureOwner */
	    /* freed by TSS_EfiSignatureList_Free */
	    tmpptr = malloc(signatureDataLength);
	    if (tmpptr != NULL) {
		nextSignatureData->SignatureData = tmpptr;
	    }
	    else {
		printf("TSS_EfiSignatureList_ReadBuffer: Error allocating %u bytes\n",
		       signatureDataLength);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	/* unmarshal the signature data */
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(nextSignatureData->SignatureData,
				      signatureDataLength,
				      event, eventSize);
	}
    }
    return rc;
}

/* TSS_EfiSignatureList_Trace() traces one TSS_EFI_SIGNATURE_LIST.

   There can be more than one TSS_EFI_SIGNATURE_LIST in a TSS_UEFI_VARIABLE_DATA
*/

static void     TSS_EfiSignatureList_Trace(TSS_EFI_SIGNATURE_LIST *signatureList)
{
    int rc;
    size_t guidIndex;
    uint32_t count;

    guid_printf("SignatureType GUID", signatureList->SignatureType);
    printf("  SignatureListSize %u\n", signatureList->SignatureListSize);
    printf("  SignatureHeaderSize %u\n", signatureList->SignatureHeaderSize);
    /* FIXME trace SignatureHeader if not NULL */
    printf("  SignatureSize %u\n", signatureList->SignatureSize);
    printf("  signaturesCount %u\n", signatureList->signaturesCount);

    /* trace based on the guid type */
    rc = TSS_EFI_GetGuidIndex(&guidIndex, signatureList->SignatureType);
    if (rc != 0) {
	printf("  GUID unknown\n");
    }
    for (count = 0 ; (rc == 0) && (count < signatureList->signaturesCount) ; count++) {
	guid_printf("SignatureOwner GUID", (signatureList->Signatures + count)->SignatureOwner);
	switch (guidTable[guidIndex].type) {
	  case GUID_TYPE_X509_CERT:
#ifndef TPM_TSS_MBEDTLS
	      {
		  X509 *x509 = NULL;
		  unsigned char *tmpData = NULL;
		  /* tmp pointer because d2i moves the pointer */
		  tmpData = (signatureList->Signatures + count)->SignatureData;
		  x509 = d2i_X509(NULL,			/* freed by caller */
				  (const unsigned char **)&tmpData,
				  signatureList->SignatureSize - TSS_EFI_GUID_SIZE);
		  if (x509 != NULL) {
		      X509_print_fp(stdout, x509);
		  }
		  else {
		      printf("  X509 Certificate invalid\n");
		  }
		  X509_free(x509);
		  x509 = NULL;	/* for next time through loop */
	      }
#endif	/* TPM_TSS_MBEDTLS */
	    break;
	  case  GUID_TYPE_SHA256:
	    TSS_PrintAll("    SHA-256",
			 (signatureList->Signatures + count)->SignatureData,
			 signatureList->SignatureSize - TSS_EFI_GUID_SIZE);
	    break;
	  case GUID_TYPE_UNSUPPORTED:
	  default:
	    /* FIXME add other types, need sample logs */
	    break;
	}
    }
    return;
}

/* EV_EFI_VARIABLE_DRIVER_CONFIG */

static void TSS_EfiVariableDriverConfig_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uint32_t count;

    /* common TSS_UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableData_Trace(efiData);
    /* EV_EFI_VARIABLE_DRIVER_CONFIG trace */
    /* if the variable was SecureBoot */
    switch (uefiVariableData->variableDataTag) {
      case TSS_VAR_SECUREBOOT:
      case TSS_VAR_AUDITMODE:
      case TSS_VAR_DEPLOYEDMODE:
      case TSS_VAR_SETUPMODE:
	printf("  Enabled: %s\n",
	       uefiVariableData->variableDriverConfig.enabled ? "yes" : "no");
	break;
      case TSS_VAR_PK:
      case TSS_VAR_KEK:
      case TSS_VAR_DB:
      case TSS_VAR_DBR:
      case TSS_VAR_DBT:
      case TSS_VAR_DBX:
      case TSS_VAR_MOKLIST:
      case TSS_VAR_MOKLISTX:
	/* intentional fall through */
	printf("  signatureListCount: %u\n",
	       uefiVariableData->variableDriverConfig.signatureListCount);
	for (count = 0 ; count < uefiVariableData->variableDriverConfig.signatureListCount ;
	     count++) {
	    TSS_EfiSignatureList_Trace(uefiVariableData->variableDriverConfig.signatureList + count);
	}
	break;
      default:
	TSS_PrintAll("    Variable unsupported:",
		     uefiVariableData->VariableData,
		     (uint32_t)uefiVariableData->VariableDataLength);
	break;
    }
    return;
}

static uint32_t TSS_EfiVariableDriverConfig_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData;

    if (rc == 0) {
    }
    return rc;
}

/* TSS_UEFI_VARIABLE_DATA handler for event EV_EFI_VARIABLE_BOOT

   The event can either be the BootOrder (uint16_t) or a boot variable description.
*/

static void TSS_EfiVariableBoot_Init(TSST_EFIData *efiData)
{
    TSS_EfiVariableData_Init(efiData);
    /* the union members are initialized when the tag is set */
    return;
}

static void TSS_EfiVariableBoot_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    if (uefiVariableData->variableDataTag == TSS_VAR_BOOTORDER) {
	TSS_EfiVariableBootOrder_Free(&uefiVariableData->variableBootOrder);
    }
    else if (uefiVariableData->variableDataTag == TSS_VAR_BOOTPATH) {
	TSS_EfiVariableBootPath_Free(&uefiVariableData->variableBoot);
    }
    TSS_EfiVariableData_Free(efiData);
    return;
}

/* TSST_EFIData holds TSS_UEFI_VARIABLE_DATA.
   TSS_UEFI_VARIABLE_DATA holds standard header, a tag, and a union.
   The union here is either TSS_VARIABLE_BOOT_ORDER or TSS_VARIABLE_BOOT.
*/

static uint32_t TSS_EfiVariableBoot_ReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index; 
    pcrIndex = pcrIndex;

    /* common code for TSS_UEFI_VARIABLE_DATA */
    if (rc == 0) {
	rc = TSS_EfiVariableData_ReadBuffer(efiData, &event, &eventSize);
    }
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    /* specific code for EV_EFI_VARIABLE_BOOT */
    /* is the UnicodeName string BootOrder */
    if (rc == 0) {
	/* unmarshal BootOrder - List of uint16_t */
	if (uefiVariableData->variableDataTag == TSS_VAR_BOOTORDER) {
	    TSS_VARIABLE_BOOT_ORDER *variableBootOrder = &uefiVariableData->variableBootOrder;
	    TSS_EfiVariableBootOrder_Init(variableBootOrder);
	    rc = TSS_EfiVariableBootOrder_ReadBuffer(variableBootOrder,
						     uefiVariableData->VariableData,
						     (uint32_t)uefiVariableData->VariableDataLength);
	}
	/* unmarshal boot path */
	else {
	    TSS_VARIABLE_BOOT *variableBoot = &uefiVariableData->variableBoot;
	    /* default of not BootOrder, for the free */
	    uefiVariableData->variableDataTag = TSS_VAR_BOOTPATH;
	    TSS_EfiVariableBootPath_Init(variableBoot);		/* for the free */
	    rc = TSS_EfiVariableBootPath_ReadBuffer(variableBoot,
						    uefiVariableData->VariableData,
						    uefiVariableData->VariableDataLength);
	}
	/* trace the GUID and Var as errors */
	if (rc != 0) {
	    printf("TSS_EfiVariableBoot_ReadBuffer: "
		   "Error in TSS_UEFI_VARIABLE_DATA structure tag %u\n",
		   uefiVariableData->variableDataTag);
	    TSS_EfiVariableData_Trace(efiData);
	}
    }
    return rc;
}

static void     TSS_EfiVariableBootOrder_Init(TSS_VARIABLE_BOOT_ORDER *variableBootOrder)
{
    variableBootOrder->bootOrderListCount = 0;
    variableBootOrder->bootOrderList = NULL;
    return;
}

static void     TSS_EfiVariableBootOrder_Free(TSS_VARIABLE_BOOT_ORDER *variableBootOrder)
{
    free(variableBootOrder->bootOrderList);
    return;
}

/* TSS_EfiVariableBootOrder_ReadBuffer() unmarshals the BootOrder variable data into an array of uint16_t
*/

static uint32_t TSS_EfiVariableBootOrder_ReadBuffer(TSS_VARIABLE_BOOT_ORDER *variableBootOrder,
						    uint8_t *VariableData, uint32_t VariableDataLength)
{
    uint32_t rc = 0;
    uint32_t count;

    if (rc == 0) {
	if ((VariableDataLength % 2) == 0) {
	    variableBootOrder->bootOrderListCount = VariableDataLength / 2;
	}
	else {
	    printf("TSS_EfiVariableBootOrder_ReadBuffer: Error in VariableDataLength %u\n",
		   VariableDataLength);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* malloc the array of boot order uint16_t */
    if (rc == 0) {
        /* freed by TSS_EfiVariableData_Init */
	variableBootOrder->bootOrderList =
	    malloc(variableBootOrder->bootOrderListCount * sizeof(uint16_t));

	if (variableBootOrder->bootOrderList == NULL) {
	    printf("TSS_EfiVariableBootOrder_ReadBuffer: Error allocating %u bytes\n",
		   (unsigned int)(variableBootOrder->bootOrderListCount * sizeof(uint16_t)));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* iterate and build the bootOrderList array of uint16_t */
    for (count = 0 ; (rc == 0) && (count < variableBootOrder->bootOrderListCount) ; count++) {
	uint16_t *nextBootOrderList = variableBootOrder->bootOrderList + count;
	rc = TSS_UINT16LE_Unmarshal(nextBootOrderList, 
				    &VariableData, &VariableDataLength);
    }
    return rc;
}

static void     TSS_EfiVariableBootPath_Init(TSS_VARIABLE_BOOT *variableBoot)
{
    variableBoot->Description = NULL;
    variableBoot->UefiDevicePathCount = 0;
    variableBoot->UefiDevicePath = NULL;
    return;
}

static void     TSS_EfiVariableBootPath_Free(TSS_VARIABLE_BOOT *variableBoot)
{
    uint32_t count;

    free(variableBoot->Description);
    for (count = 0 ; count < variableBoot->UefiDevicePathCount ; count++) {
	TSS_UEFI_DEVICE_PATH *uefiDevicePath = variableBoot->UefiDevicePath + count;
	TSS_UefiDevicePath_Free(uefiDevicePath);
    }
    free(variableBoot->UefiDevicePath);
    return;
}

static uint32_t TSS_EfiVariableBootPath_ReadBuffer(TSS_VARIABLE_BOOT *variableBoot,
						   void *VariableData, uint64_t VariableDataLength)
{
    uint32_t rc = 0;
    uint8_t *event = VariableData;
    uint32_t eventSize = (uint32_t)VariableDataLength;

    /* this parser is in-line, into the TSS_VARIABLE_BOOT structure */
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&variableBoot->Attributes,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&variableBoot->FilePathListLength,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UCS2_Unmarshal(&variableBoot->Description,	/* must be freed */
				&variableBoot->DescriptionLength,
				&event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UefiDevicePathList_ReadBuffer(&variableBoot->UefiDevicePath,
					       &variableBoot->UefiDevicePathCount,
					       event, variableBoot->FilePathListLength);
    }
    return rc;
}

static void TSS_EfiVariableBoot_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uint32_t count;

    /* common TSS_UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableData_Trace(efiData);
    /* is the UnicodeName string BootOrder */
    if (uefiVariableData->variableDataTag == TSS_VAR_BOOTORDER) {
	TSS_VARIABLE_BOOT_ORDER *variableBootOrder = &uefiVariableData->variableBootOrder;
	printf("  Boot Order: ");
	for (count = 0 ; count < variableBootOrder->bootOrderListCount ; count++) {
            printf("Boot%04x ", *(variableBootOrder->bootOrderList + count));
	}
	printf("\n");
    }
    else if (uefiVariableData->variableDataTag == TSS_VAR_BOOTPATH) {
	TSS_VARIABLE_BOOT *variableBoot = &uefiVariableData->variableBoot;
	printf("  Attributes: %08x\n", variableBoot->Attributes);
	printf("  FilePathListLength: %hu\n", variableBoot->FilePathListLength);
	ucs2_printf("Description: ", variableBoot->Description,
		    variableBoot->DescriptionLength * 2);
	for (count = 0 ; count < variableBoot->UefiDevicePathCount ; count++) {
	    TSS_UefiDevicePath_Trace(variableBoot->UefiDevicePath + count);
	}
    }
    return;
}

static uint32_t TSS_EfiVariableBoot_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData;

    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_VARIABLE_AUTHORITY */

static void     TSS_EfiVariableAuthority_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_EfiVariableData_Init(efiData);
    uefiVariableData->authoritySignatureData.SignatureData = NULL;
    uefiVariableData->authoritySignatureData.SignatureLength = 0;
   return;
}

static void     TSS_EfiVariableAuthority_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    free(uefiVariableData->authoritySignatureData.SignatureData);
    TSS_EfiVariableData_Free(efiData);
    return;
}

static uint32_t TSS_EfiVariableAuthority_ReadBuffer(TSST_EFIData *efiData,
						   uint8_t *event, uint32_t eventSize,
						   uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    size_t index; 
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_EfiVariableData_ReadBuffer(efiData,
					   &event, &eventSize);
    }
    if (rc == 0) {
	TSS_EFI_GetNameIndex(&index,
			     uefiVariableData->UnicodeName,
			     uefiVariableData->UnicodeNameLength);
	uefiVariableData->variableDataTag = tagTable[index].tag;
    }
    if (rc == 0) {
	TSS_AUTHORITY_SIGNATURE_DATA *authoritySignatureData =
	    &uefiVariableData->authoritySignatureData;
	/* tmp because unmarshal moves pointers */
	uint8_t *tmpVarData = uefiVariableData->VariableData;
	uint32_t tmpVarDataLength = (uint32_t)uefiVariableData->VariableDataLength;

	/* db has an owner, shim does not */
	if (uefiVariableData->variableDataTag == TSS_VAR_DB) {
	    /* unmarshal the signature owner */
	    if (rc == 0) {
		rc = TSS_Array_Unmarshalu(authoritySignatureData->SignatureOwner,
					  sizeof(authoritySignatureData->SignatureOwner),
					  &tmpVarData, &tmpVarDataLength);
	    }
	}
	/* intentional fall through for DB */
	if ((uefiVariableData->variableDataTag == TSS_VAR_DB) ||
	    (uefiVariableData->variableDataTag == TSS_VAR_SHIM) ||
	    (uefiVariableData->variableDataTag == TSS_VAR_MOKLIST)) {

	    /* assume the rest of the event is the certificate since there is no SignatureSize
	       field */
	    if (rc == 0) {
		authoritySignatureData->SignatureLength = tmpVarDataLength;
		authoritySignatureData->SignatureData =
		    malloc(authoritySignatureData->SignatureLength);
		if (authoritySignatureData->SignatureData == NULL) {
		    printf("TSS_EfiVariableAuthorityReadBuffer: Error allocating %u bytes\n",
			   (unsigned int)authoritySignatureData->SignatureLength);
		    rc = TSS_RC_OUT_OF_MEMORY;
		}
	    }
	    /* unmarshal the signature data */
	    if (rc == 0) {
		rc = TSS_Array_Unmarshalu(authoritySignatureData->SignatureData,
					  authoritySignatureData->SignatureLength,
					  &tmpVarData, &tmpVarDataLength);
	    }
	    /* trace the GUID and Var as errors */
	    if (rc != 0) {
		printf("TSS_EfiVariableAuthorityReadBuffer: Error with tag %u\n",
		       uefiVariableData->variableDataTag);
		TSS_EfiVariableData_Trace(efiData);
	    }
	    /* FIXME sanity check for all consumed */
	    /* tmpVarDataLength should be zero.  This is underspecified in PFP */
	}
    }
    return rc;
}

static void TSS_EfiVariableAuthority_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    TSS_AUTHORITY_SIGNATURE_DATA *authoritySignatureData =
	&uefiVariableData->authoritySignatureData;

    /* common TSS_UEFI_VARIABLE_DATA trace */
    TSS_EfiVariableData_Trace(efiData);
    /* not part of UEFI structure */
    printf("  SignatureLength: %u\n", authoritySignatureData->SignatureLength);
    /* db has an owner, shim does not */
    if (uefiVariableData->variableDataTag == TSS_VAR_DB) {
	guid_printf("SignatureOwner GUID", authoritySignatureData->SignatureOwner);
    }
#ifndef TPM_TSS_MBEDTLS
    if ((uefiVariableData->variableDataTag == TSS_VAR_DB) ||
	(uefiVariableData->variableDataTag == TSS_VAR_SHIM) ||
	(uefiVariableData->variableDataTag == TSS_VAR_MOKLIST)) {

	X509 *x509 = NULL;
	unsigned char *tmpData = NULL;
	tmpData = authoritySignatureData->SignatureData;
	x509 = d2i_X509(NULL,			/* freed by caller */
			(const unsigned char **)&tmpData,
			authoritySignatureData->SignatureLength);
	if (x509 != NULL) {
	    X509_print_fp(stdout, x509);
	}
	else {
	    printf("  X509 Certificate invalid\n");
	}
	X509_free(x509);
	x509 = NULL;
    }
#endif	/* TPM_TSS_MBEDTLS */
    return;
}

static uint32_t TSS_EfiVariableAuthority_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_VARIABLE_DATA *uefiVariableData = &efiData->efiData.uefiVariableData;
    uefiVariableData = uefiVariableData ;

    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_BOOT_SERVICES_DRIVER handler

   The event field MUST contain a TSS_UEFI_IMAGE_LOAD_EVENT structure.
*/

static void TSS_EfiBootServices_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    uefiImageLoadEvent->DevicePath = NULL;
    uefiImageLoadEvent->Path = NULL;
    uefiImageLoadEvent->UefiDevicePathCount = 0;
    uefiImageLoadEvent->UefiDevicePath = NULL;
    return;
}

static void TSS_EfiBootServices_Free(TSST_EFIData *efiData)
{
    uint32_t count;
    TSS_UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    free(uefiImageLoadEvent->DevicePath);
    free(uefiImageLoadEvent->Path);
    for (count = 0 ; count < uefiImageLoadEvent->UefiDevicePathCount ; count++) {
	TSS_UEFI_DEVICE_PATH *uefiDevicePath = uefiImageLoadEvent->UefiDevicePath + count;
	TSS_UefiDevicePath_Free(uefiDevicePath);
    }
    free(uefiImageLoadEvent->UefiDevicePath);
    return;
}

static uint32_t TSS_EfiBootServices_ReadBuffer(TSST_EFIData *efiData,
					       uint8_t *event, uint32_t eventSize,
					       uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLocationInMemory,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLengthInMemory,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->ImageLinkTimeAddress,
				    &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiImageLoadEvent->LengthOfDevicePath,
				    &event, &eventSize);
    }
    /* sanity check the length since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > EFI_LENGTH_MAX) {
	    printf("TSS_EfiBootServices_ReadBuffer: LengthOfDevicePath %" PRIu64 " too large\n",
		   uefiImageLoadEvent->LengthOfDevicePath);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the DevicePath array */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > 0) {
	    /* freed by TSS_EfiBootServices_Free */
	    uefiImageLoadEvent->DevicePath = malloc((size_t)uefiImageLoadEvent->LengthOfDevicePath);
	    if (uefiImageLoadEvent->DevicePath == NULL) {
		printf("TSS_EfiBootServices_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiImageLoadEvent->LengthOfDevicePath));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal DevicePath to byte stream */
    if (rc == 0) {
	if (uefiImageLoadEvent->LengthOfDevicePath > 0) {
	    rc = TSS_Array_Unmarshalu(uefiImageLoadEvent->DevicePath,
				      (uint16_t)uefiImageLoadEvent->LengthOfDevicePath,
				      &event, &eventSize);
	}
	else {
	    /* FIXME is LengthOfDevicePath zero an error ? */
	}
    }
    /* unmarshal the device path array */
    if (rc == 0) {
	rc = TSS_UefiDevicePathList_ReadBuffer(&uefiImageLoadEvent->UefiDevicePath,
					       &uefiImageLoadEvent->UefiDevicePathCount,
					       uefiImageLoadEvent->DevicePath,
					       (uint32_t)uefiImageLoadEvent->LengthOfDevicePath);
    }
    return rc;
}

static void TSS_EfiBootServices_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    uint32_t count;

    printf("  Image location in memory: %016" PRIx64 "\n", uefiImageLoadEvent->ImageLocationInMemory);
    printf("  Image length in memory: %" PRIu64 "\n", uefiImageLoadEvent->ImageLengthInMemory);
    printf("  Image link time address: %016" PRIx64 "\n", uefiImageLoadEvent->ImageLinkTimeAddress);
    TSS_PrintAll("  DevicePath:",
		 uefiImageLoadEvent->DevicePath, (uint32_t)uefiImageLoadEvent->LengthOfDevicePath);
    printf("  UefiDevicePathCount: %u\n", uefiImageLoadEvent->UefiDevicePathCount);

    for (count = 0 ; count < uefiImageLoadEvent->UefiDevicePathCount ; count++) {
	TSS_UefiDevicePath_Trace(uefiImageLoadEvent->UefiDevicePath + count);
    }
    return;
}

static uint32_t TSS_EfiBootServices_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_IMAGE_LOAD_EVENT *uefiImageLoadEvent = &efiData->efiData.uefiImageLoadEvent;
    /* needs iterator over count */
    rc = TSS_UefiDevicePath_ToJson(uefiImageLoadEvent->UefiDevicePath);
    return rc;
}

/* TSS_UEFI_DEVICE_PATH  */

/* UefiDevicePath is an array of TSS_UEFI_DEVICE_PATH.  This is common code for
   TSS_EfiBootServices_ReadBuffer() and TSS_EfiVariableBootPath_ReadBuffer(),

   Loop through the event, realloc to grow the array, and unmarshal the next element.
*/

static uint32_t TSS_UefiDevicePathList_ReadBuffer(TSS_UEFI_DEVICE_PATH **UefiDevicePath,
						  uint32_t *UefiDevicePathCount,
						  uint8_t *devicePath,
						  uint32_t lengthOfDevicePath)
{
    uint32_t rc = 0;
 
    while ((rc == 0) && (lengthOfDevicePath > 0)) {
	TSS_UEFI_DEVICE_PATH *nextDevicePath;
	if (rc == 0) {
	    void *tmpptr;				/* for realloc */
	    /* freed by TSS_EfiBootServices_Free() */
	    tmpptr = realloc(*UefiDevicePath,
			     sizeof(TSS_UEFI_DEVICE_PATH) * ((size_t)(*UefiDevicePathCount)+1));
	    if (tmpptr != NULL) {
		*UefiDevicePath = tmpptr;
		nextDevicePath =
		    *UefiDevicePath + *UefiDevicePathCount;
		(*UefiDevicePathCount)++;
	    }
	    else {
		printf("TSS_UefiDevicePathList_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)sizeof(TSS_UEFI_DEVICE_PATH) *
		       *UefiDevicePathCount);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    TSS_UefiDevicePath_Init(nextDevicePath);	/* for safe free */
	    rc = TSS_UefiDevicePath_ReadBuffer(nextDevicePath,
					       &devicePath, &lengthOfDevicePath);
	}
    }
    return rc;
}

static void TSS_UefiDevicePath_Init(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uefiDevicePath->data = NULL;
    uefiDevicePath->bufferLength = 0;
    uefiDevicePath->buffer = NULL;
    uefiDevicePath->unionBufferLength = 0;
    uefiDevicePath->unionBuffer = NULL;
   return;
}

static void TSS_UefiDevicePath_Free(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    free(uefiDevicePath->data);
    free(uefiDevicePath->buffer);
    free(uefiDevicePath->unionBuffer);
    return;
}

static uint32_t TSS_UefiDevicePath_ReadBuffer(TSS_UEFI_DEVICE_PATH *uefiDevicePath,
					      uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    uint32_t trc = 0;

    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&uefiDevicePath->protocol.Type,
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&uefiDevicePath->protocol.SubType,
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT16LE_Unmarshal(&uefiDevicePath->protocol.Length,
				    event, eventSize);
    }
#if 0
    printf("TSS_UefiDevicePath_ReadBuffer: Type %02x SubType %02x length %hu rc %08x\n",
	   uefiDevicePath->protocol.Type, uefiDevicePath->protocol.SubType,
	   uefiDevicePath->protocol.Length, rc);
#endif
    /* sanity check length, subtract because length includes protocol header  */
    if (rc == 0) {
	if (uefiDevicePath->protocol.Length > (*eventSize + sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL))) {
	    printf("TSS_UefiDevicePath_ReadBuffer protocol.Length %u too large\n",
		   uefiDevicePath->protocol.Length);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the data array */
    if (rc == 0) {
	if (uefiDevicePath->protocol.Length > sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL)) {
	    /* freed by TSS_EfiVariableData_Free, length is total, subtract the
	       TSS_EFI_DEVICE_PATH_PROTOCOL */
	    uefiDevicePath->data = malloc(uefiDevicePath->protocol.Length -
					  sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
	    if (uefiDevicePath->data == NULL) {
		printf("TSS_UefiDevicePath_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)(uefiDevicePath->protocol.Length));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    if (rc == 0) {
	size_t index;
	trc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.Type,
					 sizeof(efiDevicePathProtocolTypeTable),
					 efiDevicePathProtocolTypeTable);
	if (trc == 0) {
	    rc = efiDevicePathProtocolTypeTable[index].readBufferFunction(uefiDevicePath,
									  event, eventSize);
	}
	/* Type unknown / unsupported */
	else {
	    rc = TSS_Array_Unmarshalu(uefiDevicePath->data,
				      uefiDevicePath->protocol.Length -
				      sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL),
				      event, eventSize);
	}
    }
    return rc;
}

static void TSS_UefiDevicePath_Trace(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t 	rc;
    size_t 	index;

    /* index into the EFI_DEVICE_PATH_PROTOCOL Type table */
    rc = TSS_EFI_GetDevicePathIndex(&index, uefiDevicePath->protocol.Type,
				    sizeof(efiDevicePathProtocolTypeTable),
				    efiDevicePathProtocolTypeTable);
    if (rc == 0) {
	printf("    Type %02x %s\n",
	       uefiDevicePath->protocol.Type,
	       efiDevicePathProtocolTypeTable[index].text);
	efiDevicePathProtocolTypeTable[index].traceFunction(uefiDevicePath);
    }
    else {
	printf("    Type    %02x\n", uefiDevicePath->protocol.Type);
	printf("    SubType %02x\n", uefiDevicePath->protocol.SubType);
	TSS_PrintAll("   Data:",
		     uefiDevicePath->data, uefiDevicePath->protocol.Length - 
		     sizeof(TSS_EFI_DEVICE_PATH_PROTOCOL));
    }
    return;
}

static uint32_t TSS_UefiDevicePath_ToJson(TSS_UEFI_DEVICE_PATH *uefiDevicePath)
{
    uint32_t rc = 0;
    uefiDevicePath = uefiDevicePath;
    return rc;
}

/* EV_EFI_GPT_EVENT */

static void TSS_EfiGptEvent_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    uefiGptData->Partitions = NULL;
    uefiGptData->UEFIPartitionHeader.Reserved2 = NULL;
    return;
}

static void TSS_EfiGptEvent_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    free(uefiGptData->Partitions);
    free(uefiGptData->UEFIPartitionHeader.Reserved2);
    return;
}

static uint32_t TSS_EfiGptEvent_ReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize,
					  uint32_t pcrIndex)
{
    uint32_t rc = 0;
    uint64_t partitionCount;
    TSS_UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader = &(uefiGptData->UEFIPartitionHeader);

    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_EfiPartitionHeader_ReadBuffer(efiPartitionHeader,
					      &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiGptData->NumberOfPartitions, &event, &eventSize);
    }
    if (rc == 0) {
	if (uefiGptData->NumberOfPartitions > EFI_LENGTH_MAX) {
	    printf("TSS_EfiVariableData_ReadBuffer: VariableDataLength %" PRIu64 " too large\n",
		   uefiGptData->NumberOfPartitions);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    if (rc == 0) {
	if (uefiGptData->NumberOfPartitions > 0) {
	    /* freed by TSS_EfiGptEvent_Free */
	    uefiGptData->Partitions =
		malloc((size_t)uefiGptData->NumberOfPartitions * sizeof(TSS_UEFI_PARTITION_ENTRY));
	    if (uefiGptData->Partitions == NULL) {
		printf("TSS_EfiGptEvent_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)
		       (uefiGptData->NumberOfPartitions * sizeof(TSS_UEFI_PARTITION_ENTRY)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    for (partitionCount = 0 ;
	 (rc == 0) && (partitionCount < uefiGptData->NumberOfPartitions) ;
	 partitionCount++) {

	TSS_UEFI_PARTITION_ENTRY *entry = uefiGptData->Partitions + partitionCount;
	if (rc == 0) {
	    rc = TSS_EfiPartitionEntry_ReadBuffer(entry, &event, &eventSize);
	}
    }
    return rc;
}

static uint32_t TSS_EfiPartitionHeader_ReadBuffer(TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader,
						  uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    uint32_t startEventSize = *eventSize; /* track what was unmarshaled, excluding reserved */

    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->Signature, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->Revision, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->HeaderSize, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->HeaderCRC32, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->Reserved1, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->MyLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->AlternateLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->FirstUsableLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->LastUsableLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(efiPartitionHeader->DiskGUID,
				  sizeof(efiPartitionHeader->DiskGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&efiPartitionHeader->PartitionEntryLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->NumberOfPartitionEntries, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->SizeOfPartitionEntry, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Unmarshal(&efiPartitionHeader->PartitionEntryArrayCRC32, event, eventSize);
    }
    /* skip the reserved area for now */
    if (rc == 0) {
	uint32_t endEventSize = *eventSize;
	uint32_t usedBytes = startEventSize - endEventSize;  		/* used in the header */
	uint32_t skipBytes = efiPartitionHeader->HeaderSize - usedBytes; /* the reserved field */
	if (skipBytes <= *eventSize) {		/* bounds check */
	    /* skip unused bytes that are reserved */
	    *event += skipBytes;
	    *eventSize -= skipBytes;
	}
	else {	/* HeaderSize inconsistent with eventSize */
	    rc = TPM_RC_INSUFFICIENT;
	}
    }
    return rc;
}

static uint32_t TSS_EfiPartitionEntry_ReadBuffer(TSS_UEFI_PARTITION_ENTRY *entry,
						 uint8_t **event, uint32_t *eventSize)
{
    uint32_t rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->PartitionTypeGUID,
				  sizeof(entry->PartitionTypeGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->UniquePartitionGUID,
				  sizeof(entry->UniquePartitionGUID),
				  event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->StartingLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->EndingLBA, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&entry->Attributes, event, eventSize);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(entry->PartitionName,
				  sizeof(entry->PartitionName),
				  event, eventSize);
    }
    return rc;
}

static void TSS_EfiGptEvent_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader = &(uefiGptData->UEFIPartitionHeader);
    uint64_t partitionCount;

    TSS_EfiPartitionHeader_Trace(efiPartitionHeader);
    printf("  Number of Partitions: %" PRIu64 "\n\n", uefiGptData->NumberOfPartitions);
    for (partitionCount = 0 ;
	 partitionCount < uefiGptData->NumberOfPartitions ;
	 partitionCount++) {

	TSS_UEFI_PARTITION_ENTRY *entry = uefiGptData->Partitions + partitionCount;
	TSS_EfiPartitionEntry_Trace(entry);
    }
    return;
}

static void TSS_EfiPartitionHeader_Trace(TSS_UEFI_PARTITION_TABLE_HEADER *efiPartitionHeader)
{
    printf("  Signature %016" PRIx64 "\n", efiPartitionHeader->Signature);
    printf("  Revision %08x\n", efiPartitionHeader->Revision);
    printf("  HeaderSize %u\n", efiPartitionHeader->HeaderSize);
    printf("  HeaderCRC32 %08x\n", efiPartitionHeader->HeaderCRC32);
    printf("  Reserved1 %u\n", efiPartitionHeader->Reserved1);
    printf("  MyLBA %016" PRIx64 "\n", efiPartitionHeader->MyLBA);
    printf("  AlternateLBA %016" PRIx64 "\n", efiPartitionHeader->AlternateLBA);
    printf("  FirstUsableLBA %016" PRIx64 "\n", efiPartitionHeader->FirstUsableLBA);
    printf("  LastUsableLBA %016" PRIx64 "\n", efiPartitionHeader->LastUsableLBA);
    guid_printf("DiskGUID", efiPartitionHeader->DiskGUID);
    printf("  PartitionEntryLBA %016" PRIx64 "\n", efiPartitionHeader->PartitionEntryLBA);
    printf("  NumberOfPartitionEntries %u\n", efiPartitionHeader->NumberOfPartitionEntries);
    printf("  SizeOfPartitionEntry %u\n", efiPartitionHeader->SizeOfPartitionEntry);
    printf("  PartitionEntryArrayCRC32 %08x\n", efiPartitionHeader->PartitionEntryArrayCRC32);
    return;
}

static void TSS_EfiPartitionEntry_Trace(TSS_UEFI_PARTITION_ENTRY *entry)
{
    guid_printf("  PartitionTypeGUID", entry->PartitionTypeGUID);
    guid_printf("  UniquePartitionGUID", entry->UniquePartitionGUID);
    printf("    StartingLBA %016" PRIx64 "\n", entry->StartingLBA);
    printf("    EndingLBA %016" PRIx64 "\n",  entry->EndingLBA);
    printf("    Attributes %016" PRIx64 "\n", entry->Attributes);
    printf("    PartitionName %.*s\n", (int)sizeof(entry->PartitionName), entry->PartitionName);
    printf("\n");
    return;
}


static uint32_t TSS_EfiGptEvent_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_GPT_DATA *uefiGptData = &efiData->efiData.uefiGptData;
    uefiGptData = uefiGptData;
    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_VERSION
   EV_POST_CODE
*/

static void TSS_Efi4bBuffer_Init(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer->size = 0;
    tss4bBuffer->buffer = NULL;
    return;
}

static void TSS_Efi4bBuffer_Free(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    free(tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_Efi4bBuffer_ReadBuffer(TSST_EFIData *efiData,
					  uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	tss4bBuffer->size = eventSize;
	/* allocate the array*/
	if (tss4bBuffer->size > 0) {
	    /* freed by TSS_Efi4bBuffer_Free */
	    tss4bBuffer->buffer = malloc(tss4bBuffer->size);
	    if (tss4bBuffer->buffer == NULL) {
		printf("TSS_Efi4bBuffer_ReadBuffer: Error allocating %u bytes\n",
		       tss4bBuffer->size);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal UnicodeName */
    if (rc == 0) {
	if (tss4bBuffer->size > 0) {
	    rc = TSS_Array_Unmarshalu(tss4bBuffer->buffer, tss4bBuffer->size,
				      &event, &eventSize);
	}
	else {
	    /* FIXME is zero an error ? */
	}
    }
    return rc;
}

/* EV_COMPACT_HASH */

static void     TSS_EfiCompactHash_Trace(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    int done = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;

    /* PCR 6 event holds a string */
    if (efiData->pcrIndex == 6) {
	done = 1;
	printf("  Compact Hash: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    }
    /* PCR 11 holds MS Bitlocker status, see EV_COMPACT_HASH_TABLE */
    else if (efiData->pcrIndex == 11) {
	size_t index = 0;
	if (tss4bBuffer->size == sizeof(((EV_COMPACT_HASH_TABLE *)NULL)->value)) {
	    rc = TSS_EFI_GetCompactHashIndex(&index, tss4bBuffer->buffer);
	}
	if (rc == 0) {		/* found an entry */
	    const char *text = compactHashTable[index].text;
	    done = 1;
	    printf("  Compact Hash: %s\n", text);
	}
    }
    if (!done) {
	TSS_PrintAll("    Compact Hash unsupported",
		     tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

static uint32_t TSS_EfiCompactHash_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;

    if (rc == 0) {
    }
    return rc;
}

/* EV_IPL */

static void     TSS_EfiIpl_Trace(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    uint8_t type;
    uint32_t length;
    uint8_t *buffer = tss4bBuffer->buffer;
    uint32_t size = tss4bBuffer->size;

    /* unspecified, this is not in a structure yet, because this is just a guess */
    while ((rc == 0) && (size > 0)) {
	/* if the first byte is printable, guess it's a nul terminated string */
	if (isprint(tss4bBuffer->buffer[0])) {
	    printf("  IPL: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
	    size = 0;	/* consume the entire event */
	}
	/* else they are TLV tuples */
	else {
	    if (rc == 0) {
		rc = TSS_UINT8_Unmarshalu(&type, &buffer, &size);
	    }
	    if (rc == 0) {
		rc = TSS_UINT32_Unmarshalu(&length, &buffer, &size);
	    }
	    if (rc == 0) {
		if (length <= size) {
		    switch (type) {
		      case 0x02:
			TSS_PrintAll("  IPL: Digest", buffer, length);
			break;
		      case 0x03:
			printf("  IPL: %.*s\n", length, buffer);
			break;
		      default:
			break;
		    }
		    buffer += length;
		    size -= length;
		}
		else {
		    printf("  IPL: type %02x length %u > size %u\n", type, length, size);
		    size = 0;	/* reject the rest of the buffer */
		}
	    }
	}
    }
    return;
}

static uint32_t TSS_EfiIpl_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;

    if (rc == 0) {
    }
    return rc;
}

/* EV_IPL_PARTITION_DATA */

static void     TSS_EfiIplPartitionData_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;

    printf("  Partition Data: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiIplPartitionData_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_VERSION can be either a UCS-2 or a GUID. */

static void TSS_EfiCrtmVersion_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    int isUCS2 = 1;
    int isGuid = 1;

    isUCS2String(&isUCS2, tss4bBuffer->buffer, tss4bBuffer->size);
    /* if it's not UCS-2, it could be a GUID */
    if (!isUCS2) {
	if (tss4bBuffer->size != TSS_EFI_GUID_SIZE) {
	    isGuid = 0;
	}
    }
    if (isUCS2) {
	ucs2_printf("CRTM Version: ", tss4bBuffer->buffer, tss4bBuffer->size -2);
    }
    else if (isGuid) {
	guid_printf("CRTM Version GUID", tss4bBuffer->buffer);
    }
    else {	/* something else */
	TSS_PrintAll("CRTM Version", tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

static uint32_t TSS_EfiCrtmVersion_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_S_CRTM_CONTENTS */

static void TSS_EfiCrtmContents_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf("  CRTM Contents: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiCrtmContents_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_ACTION */

static void TSS_EfiEfiAction_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf("  EFI Action: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiEfiAction_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    if (rc == 0) {
    }
    return rc;
}

/* Event that is only a printable string */

#if 0

static uint32_t TSS_EfiChar_ReadBuffer(TSST_EFIData *efiData,
				      uint8_t *event, uint32_t eventSize, uint32_t pcrIndex)
{
    uint32_t rc = 0;
    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_Efi4bBuffer_ReadBuffer(efiData, event, eventSize, pcrIndex);
    }a
    return rc;
}

static void TSS_EfiChar_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    printf(" %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiChar_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    return rc;
}
#endif

/* EV_NO_ACTION */

static void     TSS_EvNoAction_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    if (efiData->pcrIndex == 0) {
	printf("  PCR 0: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
	printf("  Locality %u\n", tss4bBuffer->buffer[tss4bBuffer->size-1]);
    }
    /* This is purely from guesses and decompiling the events, not from any spec */
    else if (efiData->pcrIndex == 0xffffffff) {
	ucs2_printf("  No Action: ", tss4bBuffer->buffer+16, 22);
    }
    else {
	TSS_PrintAll("  No Action",
		     tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

/* EV_SEPARATOR */

static void TSS_EfiSeparator_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;

    /* By observation, the separator for thses PCRs seem to be ascii */
    if ((efiData->pcrIndex == 12) ||
	(efiData->pcrIndex == 13) ||
	(efiData->pcrIndex == 14)) {
	printf("  Separator: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    }
    else {
	TSS_PrintAll("  Separator",
		     tss4bBuffer->buffer, tss4bBuffer->size);
    }
    return;
}

static uint32_t TSS_EfiSeparator_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    return rc;
}

/* EV_ACTION */

/* PFP says these are printable strings, but not NUL terminated */

static void     TSS_EfiAction_Trace(TSST_EFIData *efiData)
{
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;

    printf("  Action: %.*s\n", tss4bBuffer->size, tss4bBuffer->buffer);
    return;
}

static uint32_t TSS_EfiAction_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS4B_BUFFER *tss4bBuffer = &efiData->efiData.tss4bBuffer;
    tss4bBuffer = tss4bBuffer;
    if (rc == 0) {
    }
    return rc;
}

/* EV_EVENT_TAG */

static void     TSS_EfiEventTag_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_TAGGED_EVENT *taggedEventList = &efiData->efiData.taggedEventList;
    taggedEventList->count = 0;
    taggedEventList->taggedEvent = NULL;
    return;
}

static void     TSS_EfiEventTag_Free(TSST_EFIData *efiData)
{
    uint32_t count;
    TSS_UEFI_TAGGED_EVENT *taggedEventList = &efiData->efiData.taggedEventList;
    for (count = 0 ; count < taggedEventList->count ; count++) {
	TSS_PCClientTaggedEvent *taggedEvent = taggedEventList->taggedEvent + count;
	free(taggedEvent->taggedEventData);
    }
    free(taggedEventList->taggedEvent);
    return;
}

static uint32_t TSS_EfiEvent_ReadBuffer(TSST_EFIData *efiData,
					uint8_t *event, uint32_t eventSize,
					uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_TAGGED_EVENT *taggedEventList = &efiData->efiData.taggedEventList;
    TSS_PCClientTaggedEvent *taggedEvent;
    pcrIndex = pcrIndex;

    while ((rc == 0) && (eventSize > 0)) {
	/* if there is more event data, unmarshal the next TSS_PCClientTaggedEvent */
	if (rc == 0) {
	    void *tmpptr;			/* for realloc */
	    /* freed by TSS_EfiEventTag_Free */
	    tmpptr = realloc(taggedEventList->taggedEvent,
			     sizeof(TSS_PCClientTaggedEvent) * ((size_t)(taggedEventList->count)+1));
	    if (tmpptr != NULL) {
		taggedEventList->taggedEvent = tmpptr;
		taggedEvent = taggedEventList->taggedEvent + taggedEventList->count;
		taggedEventList->count++;
	    }
	    else {
		printf("TSS_EfiEvent_ReadBuffer: Error allocating %lu bytes\n",
		       (unsigned long)
		       (sizeof(TSS_PCClientTaggedEvent) * ((size_t)(taggedEventList->count)+1)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    rc = TSS_UINT32LE_Unmarshal(&taggedEvent->taggedEventID, &event, &eventSize);
	}
	if (rc == 0) {
	    rc = TSS_UINT32LE_Unmarshal(&taggedEvent->taggedEventDataSize, &event, &eventSize);
	}
	/* consistency check taggedEventDataSize */
	if (rc == 0) {
	    if (taggedEvent->taggedEventDataSize > eventSize) {
		printf("TSS_EfiEvent_ReadBuffer: Error in taggedEventDataSize %u\n",
		       (unsigned int)(taggedEvent->taggedEventDataSize));
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* allocate the taggedEventData */
	if ((rc == 0) && (taggedEvent->taggedEventDataSize > 0)) {
	    taggedEvent->taggedEventData = malloc(taggedEvent->taggedEventDataSize);
	    if (taggedEvent->taggedEventData == NULL) {
		printf("TSS_EfiEvent_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)taggedEvent->taggedEventDataSize);
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if ((rc == 0) && (eventSize > 0)) {
	    rc = TSS_Array_Unmarshalu(taggedEvent->taggedEventData, taggedEvent->taggedEventDataSize,
				      &event, &eventSize);
	}
    }
    return rc;
}

static void     TSS_EfiEventTag_Trace(TSST_EFIData *efiData)
{
    uint32_t 			count;
    TSS_UEFI_TAGGED_EVENT 	*taggedEventList = &efiData->efiData.taggedEventList;
#ifndef TPM_TSS_MBEDTLS
#ifndef TPM_TSS_NORSA
#if OPENSSL_VERSION_NUMBER < 0x30000000
    RSA 		*rsaKey = NULL;
#else
    EVP_PKEY 		*rsaKey = NULL;
#endif
#endif	/* TPM_TSS_NORSA */
#endif	/* TPM_TSS_MBEDTLS */

    printf("  tagged events %u\n", taggedEventList->count);
    for (count = 0 ; count < taggedEventList->count ; count++) {
	TSS_PCClientTaggedEvent *taggedEvent = taggedEventList->taggedEvent + count;

	printf("    taggedEventID %08x\n", taggedEvent->taggedEventID);
	/* https://github.com/mattifestation/TCGLogTools/blob/master/TCGLogTools.psm1 */
	/* by observation 0x00060002 appears to be a DER encoded public key */
#if ! defined TPM_TSS_MBEDTLS && ! defined TPM_TSS_NORSA
	if (taggedEvent->taggedEventID == 0x00060002) {
	    const unsigned char *tmpData = NULL;
	    /* tmp pointer because d2i moves the pointer */
	    tmpData = taggedEvent->taggedEventData;
#if OPENSSL_VERSION_NUMBER < 0x30000000
	    rsaKey = d2i_RSA_PUBKEY(NULL, &tmpData ,taggedEvent->taggedEventDataSize); /* freed @2 */
#else
	    rsaKey = d2i_PUBKEY(NULL, &tmpData, (long)taggedEvent->taggedEventDataSize);
#endif	/* OPENSSL_VERSION_NUMBER */
	    if (rsaKey != NULL) { 	/* success */
#if OPENSSL_VERSION_NUMBER < 0x30000000
		RSA_print_fp(stdout, rsaKey, 4);
#else
		EVP_PKEY_print_public_fp(stdout, rsaKey, 4, NULL);
#endif /* OPENSSL_VERSION_NUMBER */
	    }
	    if (rsaKey != NULL) {
		TSS_RsaFree(rsaKey); 	/* @2 */
	    }
	}
	/* if it's not 0x00060002 or if the d2i fails */
	/* 0x40010001 = 'TrustBoundary' seems to be a common event.  Anyone have documentation? */
	if ((taggedEvent->taggedEventID != 0x00060002) || (rsaKey == NULL)) {
	    TSS_PrintAll("   taggedEvent",
			 taggedEvent->taggedEventData, taggedEvent->taggedEventDataSize);
	}
#else	/* TPM_TSS_MBEDTLS or TPM_TSS_NORSA */
	TSS_PrintAll("   taggedEvent",
		     taggedEvent->taggedEventData, taggedEvent->taggedEventDataSize);
#endif	/* TPM_TSS_MBEDTLS TPM_TSS_NORSA */
    }
    return;
}

static uint32_t TSS_EfiEventTag_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_TAGGED_EVENT 	*taggedEventList = &efiData->efiData.taggedEventList;
    taggedEventList = taggedEventList;
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_HANDOFF_TABLES */

static void TSS_EfiHandoffTables_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    uefiHandoffTablePointers->TableEntry = NULL;
    return;
}

static void TSS_EfiHandoffTables_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    free(uefiHandoffTablePointers->TableEntry);
    return;
}

static uint32_t TSS_EfiHandoffTables_ReadBuffer(TSST_EFIData *efiData,
						uint8_t *event, uint32_t eventSize,
						uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    pcrIndex = pcrIndex;

    rc = TSS_EfiTablePointers_ReadBuffer(uefiHandoffTablePointers,
					 &event, &eventSize,
					 pcrIndex);
    return rc;
}

/* TSS_EfiTablePointers_ReadBuffer() is common code for EV_EFI_HANDOFF_TABLES and
   EV_EFI_HANDOFF_TABLES2 */

static uint32_t
TSS_EfiTablePointers_ReadBuffer(TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers,
				uint8_t **event, uint32_t *eventSize,
				uint32_t pcrIndex)
{
    uint32_t rc = 0;
    uint64_t tableCount;

    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiHandoffTablePointers->NumberOfTables, event, eventSize);
    }
    /* sanity check the lengths since the input is untrusted.  This also guarantees that a cast to
       uint32_t is safe. */
    if (rc == 0) {
	if (uefiHandoffTablePointers->NumberOfTables >
	    EFI_LENGTH_MAX/sizeof(TSS_EFI_CONFIGURATION_TABLE)) {
	    printf("TSS_EfiHandoffTables_ReadBuffer: NumberOfTables %" PRIu64 " too large\n",
		   uefiHandoffTablePointers->NumberOfTables);
	    rc = TSS_RC_MALLOC_SIZE;
	}
    }
    /* allocate the TSS_EFI_CONFIGURATION_TABLE list */
    if (rc == 0) {
	if (uefiHandoffTablePointers->NumberOfTables > 0) {
	    /* freed by TSS_EfiHandoffTables_Free */
	    uefiHandoffTablePointers->TableEntry =
		malloc((size_t)uefiHandoffTablePointers->NumberOfTables *
		       sizeof(TSS_EFI_CONFIGURATION_TABLE));
	    if (uefiHandoffTablePointers->TableEntry == NULL) {
		printf("TSS_EfiHandoffTables_ReadBuffer: Error allocating %u bytes\n",
		       (unsigned int)
		       (uefiHandoffTablePointers->NumberOfTables *
			sizeof(TSS_EFI_CONFIGURATION_TABLE)));
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
    }
    /* unmarshal Tables */
    for (tableCount = 0 ;
	 (rc == 0) && (tableCount < uefiHandoffTablePointers->NumberOfTables) ;
	 tableCount++) {

	TSS_EFI_CONFIGURATION_TABLE *table = uefiHandoffTablePointers->TableEntry + tableCount;
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(table->VendorGuid,
				      sizeof(table->VendorGuid),
				      event, eventSize);
	}
	if (rc == 0) {
	    rc = TSS_UINT64LE_Unmarshal(&table->VendorTable, event, eventSize);
	}
    }
    return rc;
}

static void     TSS_EfiHandoffTables_Trace(TSST_EFIData *efiData)
{
    uint64_t tableCount;
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;

    printf("  NumberOfTables: %016" PRIx64 "\n", uefiHandoffTablePointers->NumberOfTables);
    for (tableCount = 0 ; tableCount < uefiHandoffTablePointers->NumberOfTables ; tableCount++) {
	TSS_EFI_CONFIGURATION_TABLE *table = uefiHandoffTablePointers->TableEntry + tableCount;
	guid_printf("VendorGuid", table->VendorGuid);
	printf("  VendorTable: %016" PRIx64 "\n", table->VendorTable);
    }
    return;
}

static uint32_t TSS_EfiHandoffTables_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&efiData->efiData.uefiHandoffTablePointers;
    uefiHandoffTablePointers = uefiHandoffTablePointers;
    if (rc == 0) {
    }
    return rc;
}

/* EV_EFI_HANDOFF_TABLE2S */

static void TSS_EfiHandoffTables2_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_HANDOFF_TABLE_POINTERS2 *uefiHandoffTablePointers2 =
	&efiData->efiData.uefiHandoffTablePointers2;
    uefiHandoffTablePointers2->TableDescription = NULL;
    uefiHandoffTablePointers2->uefiHandoffTablePointers.TableEntry = NULL;
    return;
}

static void TSS_EfiHandoffTables2_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_HANDOFF_TABLE_POINTERS2 *uefiHandoffTablePointers2 =
	&efiData->efiData.uefiHandoffTablePointers2;
    free(uefiHandoffTablePointers2->TableDescription);
    free(uefiHandoffTablePointers2->uefiHandoffTablePointers.TableEntry);
    return;
}

static uint32_t TSS_EfiHandoffTables2_ReadBuffer(TSST_EFIData *efiData,
						uint8_t *event, uint32_t eventSize,
						uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_HANDOFF_TABLE_POINTERS2 *uefiHandoffTablePointers2 =
	&efiData->efiData.uefiHandoffTablePointers2;
    pcrIndex = pcrIndex;
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&uefiHandoffTablePointers2->TableDescriptionSize,
				  &event, &eventSize);
    }
    if (rc == 0) {
	uefiHandoffTablePointers2->TableDescription =
	    malloc(uefiHandoffTablePointers2->TableDescriptionSize);
	if (uefiHandoffTablePointers2->TableDescription == NULL) {
	    printf("TSS_EfiHandoffTables2_ReadBuffer: Error allocating %u bytes\n",
		   (unsigned int)(uefiHandoffTablePointers2->TableDescriptionSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(uefiHandoffTablePointers2->TableDescription,
				  uefiHandoffTablePointers2->TableDescriptionSize,
				  &event, &eventSize);
    }
    /* the table entry read is shared between TSS_UEFI_HANDOFF_TABLE_POINTERS and
       TSS_UEFI_HANDOFF_TABLE_POINTERS2 */
    if (rc == 0) {
	TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	    &efiData->efiData.uefiHandoffTablePointers2.uefiHandoffTablePointers;
	rc = TSS_EfiTablePointers_ReadBuffer(uefiHandoffTablePointers,
					     &event, &eventSize,
					     pcrIndex);
    }
    return rc;
}

static void     TSS_EfiHandoffTables2_Trace(TSST_EFIData *efiData)
{
    uint64_t tableCount;
    TSS_UEFI_HANDOFF_TABLE_POINTERS2 *uefiHandoffTablePointers2 =
	&efiData->efiData.uefiHandoffTablePointers2;
    TSS_UEFI_HANDOFF_TABLE_POINTERS *uefiHandoffTablePointers =
	&uefiHandoffTablePointers2->uefiHandoffTablePointers;

    printf("  TableDescription: %.*s\n", 
	   (int)uefiHandoffTablePointers2->TableDescriptionSize,
	   uefiHandoffTablePointers2->TableDescription);
    printf("  NumberOfTables: %016" PRIx64 "\n", uefiHandoffTablePointers->NumberOfTables);
    for (tableCount = 0 ; tableCount < uefiHandoffTablePointers->NumberOfTables ; tableCount++) {
	TSS_EFI_CONFIGURATION_TABLE *table = uefiHandoffTablePointers->TableEntry + tableCount;
	guid_printf("VendorGuid", table->VendorGuid);
	printf("  VendorTable: %016" PRIx64 "\n", table->VendorTable);
    }
    return;
}

static uint32_t TSS_EfiHandoffTables2_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_HANDOFF_TABLE_POINTERS2 *uefiHandoffTablePointers2 =
	&efiData->efiData.uefiHandoffTablePointers2;
    uefiHandoffTablePointers2  = uefiHandoffTablePointers2;
    if (rc == 0) {
    }
    return rc;
}


/* EV_EFI_PLATFORM_FIRMWARE_BLOB2 */

static void TSS_EfiPlatformFirmwareBlob2_Init(TSST_EFIData *efiData)
{
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *uefiPlatformFirmwareBlob2 =
	&efiData->efiData.uefiPlatformFirmwareBlob2;
    uefiPlatformFirmwareBlob2->BlobDescription = NULL;
    return;
}
static void TSS_EfiPlatformFirmwareBlob2_Free(TSST_EFIData *efiData)
{
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *uefiPlatformFirmwareBlob2 =
	&efiData->efiData.uefiPlatformFirmwareBlob2;
    free(uefiPlatformFirmwareBlob2->BlobDescription);
}
static uint32_t TSS_EfiPlatformFirmwareBlob2_ReadBuffer(TSST_EFIData *efiData,
							uint8_t *event, uint32_t eventSize,
							uint32_t pcrIndex)
{
    uint32_t rc = 0;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *uefiPlatformFirmwareBlob2 =
	&efiData->efiData.uefiPlatformFirmwareBlob2;
    pcrIndex = pcrIndex;

    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&uefiPlatformFirmwareBlob2->BlobDescriptionSize,
				  &event, &eventSize);
    }
    if (rc == 0) {
	uefiPlatformFirmwareBlob2->BlobDescription =
	    malloc(uefiPlatformFirmwareBlob2->BlobDescriptionSize);
	if (uefiPlatformFirmwareBlob2->BlobDescription == NULL) {
	    printf("TSS_EfiPlatformFirmwareBlob2_ReadBuffer: Error allocating %u bytes\n",
		   (unsigned int)(uefiPlatformFirmwareBlob2->BlobDescriptionSize));
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(uefiPlatformFirmwareBlob2->BlobDescription,
				  uefiPlatformFirmwareBlob2->BlobDescriptionSize,
				  &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob2->BlobBase, &event, &eventSize);
    }
    if (rc == 0) {
	rc = TSS_UINT64LE_Unmarshal(&uefiPlatformFirmwareBlob2->BlobLength, &event, &eventSize);
    }
    return rc;
}

static void     TSS_EfiPlatformFirmwareBlob2_Trace(TSST_EFIData *efiData)
{
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *uefiPlatformFirmwareBlob2 =
	&efiData->efiData.uefiPlatformFirmwareBlob2;

    printf("  BlobDescription: %.*s\n", 
	   (int)uefiPlatformFirmwareBlob2->BlobDescriptionSize,
	   uefiPlatformFirmwareBlob2->BlobDescription);
    printf("  BlobBase: %016" PRIx64 "\n", uefiPlatformFirmwareBlob2->BlobBase);
    printf("  BlobLength: %016" PRIx64 "\n", uefiPlatformFirmwareBlob2->BlobLength);
    return;
}
static uint32_t TSS_EfiPlatformFirmwareBlob2_ToJson(TSST_EFIData *efiData)
{
    uint32_t rc = 0;
    TSS_UEFI_PLATFORM_FIRMWARE_BLOB2 *uefiPlatformFirmwareBlob2 =
	&efiData->efiData.uefiPlatformFirmwareBlob2;
    uefiPlatformFirmwareBlob2 = uefiPlatformFirmwareBlob2;
    if (rc == 0) {
    }
    return rc;
}

