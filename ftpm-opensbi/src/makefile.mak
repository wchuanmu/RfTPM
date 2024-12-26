#################################################################################
#										#
#		Windows MinGW TPM2 Makefile OpenSSL 64-bit			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2014 - 2023					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################


# Windows OpenSSL 3.1 64-bit with mingw64

CC = "c:/program files/mingw/bin/gcc.exe"

CCFLAGS = -Wall  				\
	-ggdb -O0 -c -Wnested-externs		\
	-Wno-deprecated-declarations		\
	-DTPM_WINDOWS -D_NO_OLDNAMES -D_MINGW	\
	-D_ISOC99_SOURCE -D_WIN32_WINNT=0x0603	\
	-I"c:/program files/MinGW/include"	\
	-I"c:/program files/openssl/include"	\
	-I.					\
	-DTPM_NUVOTON

LNFLAGS = -D_MT					\
	-DTPM_WINDOWS				\
	-I.					\
	-ggdb 					\
	-L.

# Shining Light OpenSSL 3.1 64-bit

LNLIBS =  	"c:/program files/openssl/bin/libcrypto-3-x64.dll" -lws2_32

all:	tpm_server.exe

CRYPTO_SUBSYSTEM = openssl
include makefile-common

OBJFILES += TcpServer.o

.PHONY:		clean
.PRECIOUS:	%.o

tpm_server.exe:	$(OBJFILES) applink.o
		$(CC) $(LNFLAGS) $(OBJFILES) -o tpm_server.exe applink.o $(LNLIBS)

clean:
		rm *.o *.exe

%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@

