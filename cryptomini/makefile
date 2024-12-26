#CC = /usr/bin/gcc
#CC = /usr/bin/riscv64-linux-gnu-gcc

CC = /opt/riscv/bin/riscv64-unknown-linux-gnu-gcc
AR = /opt/riscv/bin/riscv64-unknown-linux-gnu-ar

# CC = /opt/riscv/bin/riscv64-unknown-elf-gcc
# AR = /opt/riscv/bin/riscv64-unknown-elf-ar

#CC = riscv64-linux-gnu-gcc
#AR = riscv64-linux-gnu-ar

CCFLAGS = -c -ffunction-sections -fdata-sections \
	-Wall -Werror -ffreestanding -fno-stack-protector -fno-strict-aliasing \
	-O3 -g0 -fno-omit-frame-pointer -fno-optimize-sibling-calls	\
	-mstrict-align -mno-save-restore -mabi=lp64	-march=rv64imafdc_zicsr_zifencei -mcmodel=medany \
	-fno-pie -no-pie	\
	-mabi=lp64d			\
	-DRISC_V -DNDEBUG		\
	-DOPENSSL_NO_STDIO		\
	-I. -Iinclude	

# -nostdlib \
# -I. -Iinclude	\
# -lc -lgloss -lgcc -Wl,--start-group -lc -lgloss -Wl,--end-group -lgcc

# LNFLAGS = -static -Wl,-gc-sections



SRC_DIR     := .
SUB_SRC_DIR_AES := ./aes
SUB_SRC_DIR_BN := ./bn
SUB_SRC_DIR_CAMELLIA := ./camellia
SUB_SRC_DIR_EC := ./ec
SUB_SRC_DIR_SHA := ./sha
SUB_SRC_DIR_INTERCEPT := ./intercept

BUILD_DIR   := ./build

SRCS    := $(wildcard $(SRC_DIR)/*.c $(SUB_SRC_DIR)/*.c)
OBJS    += $(addprefix $(BUILD_DIR)/,$(patsubst %.c,%.o,$(notdir \
			$(wildcard $(SRC_DIR)/*.c $(SUB_SRC_DIR_AES)/*.c $(SUB_SRC_DIR_BN)/*.c  \
			$(SUB_SRC_DIR_EC)/*.c $(SUB_SRC_DIR_SHA)/*.c $(SUB_SRC_DIR_INTERCEPT)/*.c $(SUB_SRC_DIR_CAMELLIA)/*.c))))

libcryptomini.a: $(OBJS)
	$(AR) crs $@ $^

$(BUILD_DIR)/%.o:$(SRC_DIR)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_AES)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_BN)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_EC)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_SHA)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_INTERCEPT)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

$(BUILD_DIR)/%.o:$(SUB_SRC_DIR_CAMELLIA)/%.c
	$(CC) $(CCFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f libcryptomini.a $(OBJS)
