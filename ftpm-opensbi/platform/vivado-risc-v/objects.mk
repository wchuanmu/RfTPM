#
# SPDX-License-Identifier: BSD-2-Clause
#

PLATFORM_RISCV_XLEN = 64

FW_TEXT_START=0x80000000
FW_DYNAMIC=n
FW_JUMP=n

# Firmware with payload configuration.
FW_PAYLOAD=y

ifeq ($(PLATFORM_RISCV_XLEN), 32)
  # This needs to be 4MB aligned for 32-bit support
  FW_PAYLOAD_OFFSET=0x400000
else
  # This needs to be 2MB aligned for 64-bit support
  FW_PAYLOAD_OFFSET=0x200000
endif
#FW_PAYLOAD_FDT_ADDR=0x82200000
FW_PAYLOAD_ALIGN=0x1000

platform-objs-y += platform.o


##################################   FTPM   ###############################

CRYPTO_MINI = /workspace/rfTPM/cryptomini

FTPM_OBJS = \
	../../src/ACT_spt.o			\
	../../src/ACTCommands.o			\
	../../src/AlgorithmCap.o			\
	../../src/AlgorithmTests.o		\
	../../src/AsymmetricCommands.o		\
	../../src/Attest_spt.o			\
	../../src/AttestationCommands.o		\
	../../src/AuditCommands.o			\
	../../src/Bits.o				\
	../../src/BnConvert.o			\
    ../../src/BnEccConstants.o  \
	../../src/BnMath.o			\
    ../../src/BnMemory.o			\
    ../../src/BnToOsslMath.o			\
	../../src/BnUtil.o			\
	../../src/Cancel.o			\
	../../src/CapabilityCommands.o		\
	../../src/Clock.o				\
	../../src/ClockCommands.o			\
	../../src/CommandAudit.o			\
	../../src/CommandCodeAttributes.o		\
	../../src/CommandDispatcher.o		\
	../../src/Context_spt.o			\
	../../src/ContextCommands.o		\
	../../src/CryptCmac.o			\
	../../src/CryptDes.o			\
	../../src/CryptEccCrypt.o			\
	../../src/CryptEccData.o			\
	../../src/CryptEccKeyExchange.o		\
	../../src/CryptEccMain.o			\
	../../src/CryptEccSignature.o		\
	../../src/CryptHash.o			\
	../../src/CryptPrime.o			\
	../../src/CryptPrimeSieve.o		\
	../../src/CryptRand.o			\
	../../src/CryptRsa.o			\
	../../src/CryptSelfTest.o			\
	../../src/CryptSmac.o			\
	../../src/CryptSym.o			\
	../../src/CryptUtil.o			\
	../../src/DA.o				\
	../../src/DebugHelpers.o			\
	../../src/DictionaryCommands.o		\
	../../src/DuplicationCommands.o		\
	../../src/EACommands.o			\
	../../src/EncryptDecrypt_spt.o		\
	../../src/Entity.o			\
	../../src/Entropy.o			\
	../../src/EphemeralCommands.o		\
	../../src/ExecCommand.o			\
	../../src/ExtraData.o			\
	../../src/Global.o			\
	../../src/Handle.o			\
	../../src/HashCommands.o			\
	../../src/Hierarchy.o			\
	../../src/HierarchyCommands.o		\
	../../src/IoBuffers.o			\
	../../src/IntegrityCommands.o		\
	../../src/Locality.o			\
	../../src/LocalityPlat.o			\
	../../src/ManagementCommands.o		\
	../../src/Manufacture.o			\
	../../src/Marshal.o			\
	../../src/MathOnByteBuffers.o		\
	../../src/Memory.o			\
	../../src/NV_spt.o			\
	../../src/NVCommands.o			\
	../../src/NVDynamic.o			\
	../../src/NVMem.o				\
	../../src/NVReserved.o			\
	../../src/Object_spt.o			\
	../../src/Object.o			\
	../../src/ObjectCommands.o		\
	../../src/PCR.o				\
	../../src/PP.o				\
	../../src/PPPlat.o			\
	../../src/PlatformACT.o			\
	../../src/PlatformData.o			\
	../../src/PlatformPCR.o			\
	../../src/Policy_spt.o			\
	../../src/Power.o				\
	../../src/PowerPlat.o			\
	../../src/PrimeData.o			\
	../../src/PropertyCap.o			\
	../../src/RandomCommands.o		\
	../../src/Response.o			\
	../../src/ResponseCodeProcessing.o	\
	../../src/RsaKeyCache.o			\
	../../src/RunCommand.o			\
	../../src/Session.o			\
	../../src/SessionCommands.o		\
	../../src/SessionProcess.o		\
	../../src/SigningCommands.o		\
	../../src/StartupCommands.o		\
	../../src/SymmetricCommands.o		\
	../../src/TestingCommands.o		\
	../../src/Ticket.o			\
	../../src/Time.o				\
	../../src/TpmAsn1.o			\
	../../src/TpmBigNumThunks.o			\
	../../src/TpmEcc_Signature_ECDAA.o			\
	../../src/TpmEcc_Signature_ECDSA.o			\
    ../../src/TpmEcc_Signature_Schnorr.o			\
    ../../src/TpmEcc_Signature_SM2.o			\
    ../../src/TpmEcc_Signature_Util.o			\
    ../../src/TpmEcc_Util.o			\
	../../src/TpmFail.o			\
	../../src/TpmMath_Debug.o			\
    ../../src/TpmMath_Util.o			\
	../../src/TpmSizeChecks.o			\
	../../src/TpmToOsslSupport.o		\
	../../src/Unique.o			\
	../../src/Unmarshal.o			\
	../../src/Vendor_TCG_Test.o		\
    ../../src/VendorInfo.o		\
	../../src/X509_ECC.o			\
	../../src/X509_RSA.o			\
	../../src/X509_spt.o			\
	../../src/ntc2lib.o			\
	../../src/ntc2.o			\
	../../src/TPMCmdp.o			\
	../../src/mprv.o			\
	../../src/intercept.o		\
	../../src/ftpm-sbi-opensbi.o   	\
	../../src/ftpm.o      \
	./fatfs/diskio.o	\
	./fatfs/ff.o  		\
	./fatfs/ffsystem.o 	\
	./fatfs/ffunicode.o


#   ./ff/ff.o           
#   ./ff/bootrom.o      
#   ./ff/ffunicode.o

#../../src/ftpm-sbi-opensbi.o	



#!!!v1.4 开gc-section无输出

# 支持硬件双浮点数
PLATFORM_RISCV_ABI = lp64d

# FTPM_CFLAGS =  -ffunction-sections -fdata-sections	\
#   	-Wall  			\
# 	-Wmissing-declarations -Wmissing-prototypes -Wnested-externs \
# 	-Wno-deprecated-declarations	\
# 	-Wno-unused-function	-Wno-unused-variable	\
# 	-Wno-error=missing-prototypes	-Wno-error=maybe-uninitialized \
# 	-Wno-error=switch-unreachable	-Wno-error=stringop-overflow= \
# 	-ggdb -O0 			\
# 	-DTPM_POSIX			\
# 	-D_POSIX_			\
# 	-DTPM_NUVOTON	

FTPM_CFLAGS = 	\
  	-Wall  			\
	-Wmissing-declarations -Wmissing-prototypes -Wnested-externs \
	-Wno-deprecated-declarations	\
	-Wno-unused-function	-Wno-unused-variable	\
	-Wno-error=missing-prototypes	-Wno-error=maybe-uninitialized \
	-Wno-error=switch-unreachable	-Wno-error=stringop-overflow= \
	-Os -g0			\
	-DTPM_POSIX			\
	-D_POSIX_			\
	-DTPM_NUVOTON		\
	-DPLATFORM_TYPE=2

FTPM_CFLAGS += -DUSE_BIT_FIELD_STRUCTURES=NO -DSYM_LIB=Ossl -DHASH_LIB=Ossl -DMATH_LIB=TpmBigNum -DBN_MATH_LIB=Ossl


platform-cflags-y += $(FTPM_CFLAGS) -I$(CURDIR)/include/ftpm/ -I$(CRYPTO_MINI)/include
# platform-ldflags-y = -lcryptomini -L${CRYPTO_MINI} 

# -lc -lgcc需要重复，保证cryptomini中的memset等函数能链接到libc
# platform-ldflags-y = -lcryptomini -lc -lgcc -Wl,--start-group -lc -lgcc -Wl,--end-group -L${CRYPTO_MINI}



# platform-ldflags-y = -Wl,-Map=output.map -Wl,-gc-sections -lcryptomini -lc -lgloss -lgcc	-Wl,--start-group -lc -lgloss -Wl,--end-group -lgcc -L${CRYPTO_MINI}
platform-ldflags-y =  -lcryptomini -lc -lgloss -lgcc	-Wl,--start-group -lc -lgloss -Wl,--end-group -lgcc -L${CRYPTO_MINI}
# platform-ldflags-y = -Wl,-gc-sections -lcryptomini	-Wl,--start-group -lc -lgcc -Wl,--end-group -L${CRYPTO_MINI}

# platform-ldflags-y = -Wl,-gc-sections	-lcryptomini			
# 	-lc -lgcc -Wl,--start-group -lc -Wl,--end-group -lgcc	
# 	-L${CRYPTO_MINI}	

platform-objs-y += $(FTPM_OBJS)
