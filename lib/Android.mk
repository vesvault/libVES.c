# Set the proper paths to libs and headers

INC_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/include
LIB_CURL := /src/android/curl/$(TARGET_ARCH_ABI)/lib/libcurl.a
INC_OPENSSL := /src/android/openssl/$(TARGET_ARCH_ABI)/include
LIB_CRYPTO := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libcrypto.a
LIB_SSL := /src/android/openssl/$(TARGET_ARCH_ABI)/lib/libssl.a
INC_OQS := /src/android/liboqs/$(TARGET_ARCH_ABI)/include
LIB_OQS := /src/android/liboqs/$(TARGET_ARCH_ABI)/lib/liboqs.a

LOCAL_PATH := $(call my-dir)

LOCAL_MODULE := libVES
LOCAL_MODULE_FILENAME := libVES
LOCAL_CFLAGS += -I$(INC_OPENSSL) -I$(INC_CURL) -I$(INC_OQS)
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true

#LOCAL_SHARED_LIBRARIES += libcrypto
LOCAL_WHOLE_STATIC_LIBRARIES += libcurl libcrypto libssl liboqs
LOCAL_LDLIBS += -lz

LOCAL_SRC_FILES := libVES.c \
VESflow.c \
VESlocker.c \
libVES/Util.c \
libVES/List.c \
libVES/Cipher.c \
libVES/CiAlgo_AES.c \
libVES/VaultKey.c \
libVES/KeyAlgo_EVP.c \
libVES/KeyAlgo_OQS.c \
libVES/VaultItem.c \
libVES/Ref.c \
libVES/User.c \
libVES/File.c \
libVES/REST.c \
libVES/KeyStore.c \
libVES/Event.c \
libVES/Flow.c \
libVES/Session.c \
libVES/Watch.c \
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

include $(CLEAR_VARS)
LOCAL_MODULE := liboqs
LOCAL_MODULE_FILENAME := liboqs
LOCAL_SRC_FILES := $(LIB_OQS)
include $(PREBUILT_STATIC_LIBRARY)
