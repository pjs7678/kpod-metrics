#include "bpf_bridge.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

static void throw_bpf_exception(JNIEnv *env, const char *class_name, const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    jclass exc = (*env)->FindClass(env, class_name);
    if (exc) {
        (*env)->ThrowNew(env, exc, buf);
    }
}

static void throw_load_exception(JNIEnv *env, const char *msg) {
    throw_bpf_exception(env, "com/internal/kpodmetrics/bpf/BpfLoadException", "%s", msg);
}

static void throw_map_exception(JNIEnv *env, const char *msg) {
    throw_bpf_exception(env, "com/internal/kpodmetrics/bpf/BpfMapException", "%s", msg);
}

JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeOpenObject(
    JNIEnv *env, jobject self, jstring path) {
    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (!path_str) {
        throw_load_exception(env, "Failed to get path string");
        return 0;
    }
    struct bpf_object *obj = bpf_object__open(path_str);
    (*env)->ReleaseStringUTFChars(env, path, path_str);
    if (!obj) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "Failed to open BPF object: %s (errno=%d)",
                 strerror(errno), errno);
        throw_load_exception(env, errmsg);
        return 0;
    }
    return (jlong)(uintptr_t)obj;
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeLoadObject(
    JNIEnv *env, jobject self, jlong ptr) {
    if (ptr == 0) {
        throw_load_exception(env, "Null BPF object pointer");
        return -1;
    }
    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    int err = bpf_object__load(obj);
    if (err) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "Failed to load BPF object: %s (errno=%d)",
                 strerror(-err), -err);
        throw_load_exception(env, errmsg);
        return err;
    }
    return 0;
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeAttachAll(
    JNIEnv *env, jobject self, jlong ptr) {
    if (ptr == 0) {
        throw_load_exception(env, "Null BPF object pointer");
        return -1;
    }
    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            char errmsg[256];
            snprintf(errmsg, sizeof(errmsg), "Failed to attach program '%s': %s",
                     bpf_program__name(prog), strerror(errno));
            throw_load_exception(env, errmsg);
            return -1;
        }
    }
    return 0;
}

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeDestroyObject(
    JNIEnv *env, jobject self, jlong ptr) {
    if (ptr == 0) return;
    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    bpf_object__close(obj);
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetMapFd(
    JNIEnv *env, jobject self, jlong objPtr, jstring mapName) {
    if (objPtr == 0) {
        throw_map_exception(env, "Null BPF object pointer");
        return -1;
    }
    const char *name_str = (*env)->GetStringUTFChars(env, mapName, NULL);
    if (!name_str) {
        throw_map_exception(env, "Failed to get map name string");
        return -1;
    }
    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)objPtr;
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name_str);
    (*env)->ReleaseStringUTFChars(env, mapName, name_str);
    if (!map) {
        throw_map_exception(env, "Map not found");
        return -1;
    }
    return bpf_map__fd(map);
}

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapLookup(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint valueSize) {
    jsize keyLen = (*env)->GetArrayLength(env, key);
    jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!keyBuf) return NULL;
    void *valueBuf = malloc(valueSize);
    if (!valueBuf) {
        (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
        throw_map_exception(env, "malloc failed for value buffer");
        return NULL;
    }
    int err = bpf_map_lookup_elem(mapFd, keyBuf, valueBuf);
    (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
    if (err) {
        free(valueBuf);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, valueSize);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, valueSize, (jbyte *)valueBuf);
    }
    free(valueBuf);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapGetNextKey(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint keySize) {
    void *nextKeyBuf = malloc(keySize);
    if (!nextKeyBuf) {
        throw_map_exception(env, "malloc failed for next key buffer");
        return NULL;
    }
    int err;
    if (key == NULL) {
        err = bpf_map_get_next_key(mapFd, NULL, nextKeyBuf);
    } else {
        jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
        if (!keyBuf) {
            free(nextKeyBuf);
            return NULL;
        }
        err = bpf_map_get_next_key(mapFd, keyBuf, nextKeyBuf);
        (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
    }
    if (err) {
        free(nextKeyBuf);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, keySize);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, keySize, (jbyte *)nextKeyBuf);
    }
    free(nextKeyBuf);
    return result;
}

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapDelete(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key) {
    jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!keyBuf) return;
    bpf_map_delete_elem(mapFd, keyBuf);
    (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
}
