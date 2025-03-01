# RfTPM: A Firmware TPM Implementation for RISC-V

RfTPM is the first firmware TPM (fTPM) architecture designed for RISC-V platforms. It provides secure TPM functionalities, including isolated execution, secure storage, secure boot, and remote attestation, without requiring additional hardware costs. 

## Features
- **Firmware TPM for RISC-V**: Implements TPM functionalities without dedicated hardware.
- **Isolated Execution**: Runs as an OpenSBI extension in machine mode (M-mode) on RISC-V.
- **Secure Storage**: Ensures the integrity and confidentiality of TPM persistent data.
- **Efficient Communication**: Securely interacts with higher-level TPM applications.

## Build and Installation
### Prerequisites
Ensure that your environment includes:
- A RISC-V toolchain
- QEMU or a real RISC-V platform for testing

### Building and Installing
#### 1. Set Up Environment Variables
Before compiling, define the necessary paths:
```sh
export BUILD_DIR=/path/to/build-linux-stable-host
export FTPM_DIR=/path/to/rfTPM
export RISCV_TOOLCHAIN=/opt/riscv/bin
```
#### 2. Compile libcryptomini
```sh
make
```
#### 3. Compile ftpm-opensbi
```sh
make CROSS_COMPILE=$RISCV_TOOLCHAIN/riscv64-unknown-elf- \
     PLATFORM=generic \
     FW_PAYLOAD_PATH=$BUILD_DIR/arch/riscv/boot/Image \
     FW_PAYLOAD=y \
     PLATFORM_RISCV_XLEN=64 \
     PLATFORM_RISCV_ISA=rv64imafdc \
     PLATFORM_RISCV_ABI=lp64d
```
#### 4. Compile ftpm-driver
```sh
make -C $BUILD_DIR \
     O=$BUILD_DIR \
     ARCH=riscv \
     CROSS_COMPILE=$RISCV_TOOLCHAIN/riscv64-unknown-linux-gnu- \
     M=$FTPM_DIR/ftpm-driver modules
```
#### 5. make -f makefiletpm20
```sh
make -f makefiletpm20
```


