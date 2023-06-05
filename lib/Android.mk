# Set the proper paths to libs and headers

INC_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/include
LIB_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/lib/libcurl.a
INC_OPENSSL := /src/android/openssl/$(TARGET_ARCH_ABI)/include
LIB_CRYPTO := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libcrypto.a
LIB_SSL := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libssl.a

LOCAL_PATH := $(call my-dir)

LOCAL_MODULE := libVES
LOCAL_MODULE_FILENAME := libVES
LOCAL_CFLAGS += -I$(INC_OPENSSL) -I$(INC_CURL)
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true

#LOCAL_SHARED_LIBRARIES += libcrypto
LOCAL_WHOLE_STATIC_LIBRARIES += libcurl libcrypto libssl
LOCAL_LDLIBS += -lz

LOCAL_SRC_FILES := libVES.c \
libVES/Util.c \
libVES/List.c \
libVES/Cipher.c \
libVES/CiAlgo_AES.c \
libVES/VaultKey.c \
libVES/KeyAlgo_EVP.c \
libVES/VaultItem.c \
libVES/Ref.c \
libVES/User.c \
libVES/File.c \
libVES/REST.c \
jVar.c

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto
LOCAL_MODULE_FILENAME := libcrypto
LOCAL_SRC_FILES := $(LIB_CRYPTO)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libssl
LOCAL_MODULE_FILENAME := libssl
LOCAL_SRC_FILES := $(LIB_SSL)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcurl
LOCAL_MODULE_FILENAME := libcurl
LOCAL_SRC_FILES := $(LIB_CURL)
include $(PREBUILT_STATIC_LIBRARY)

