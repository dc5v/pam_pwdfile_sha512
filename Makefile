CC = gcc
CFLAGS = -Wall -fPIC -shared -I/usr/include/security
LDFLAGS = -lcrypt -lssl -lcrypto

TARGET_PATH := $(shell pwd)
BUILD_PATH := $(TARGET_PATH)/build
TARGET_NAME := pam_pwdfile_sha512.so

LIB_NAME = libpam
PAM_LIB_DIR := $(shell ldconfig -p | grep $(LIB_NAME) | awk '{print $$NF}' | xargs dirname | uniq)

OBJS = $(BUILD_PATH)/pam_pwdfile_sha512.o $(BUILD_PATH)/sha512_crypt.o

all: $(BUILD_PATH) $(BUILD_PATH)/$(TARGET_NAME)

$(BUILD_PATH):
	mkdir -p $(BUILD_PATH)

$(BUILD_PATH)/$(TARGET_NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(BUILD_PATH)/pam_pwdfile_sha512.o: pam_pwdfile_sha512.c sha512_crypt.h
	$(CC) $(CFLAGS) -c pam_pwdfile_sha512.c -o $@

$(BUILD_PATH)/sha512_crypt.o: sha512_crypt.c sha512_crypt.h
	$(CC) $(CFLAGS) -c sha512_crypt.c -o $@

install: all
	install -d $(PAM_LIB_DIR)
	install -m 644 $(BUILD_PATH)/$(TARGET_NAME) $(PAM_LIB_DIR)/

clean:
	rm -f $(BUILD_PATH)/*.o $(BUILD_PATH)/$(TARGET_NAME)
	rm -rf $(BUILD_PATH)
