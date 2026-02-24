#ifndef KPOD_BPF_BRIDGE_H
#define KPOD_BPF_BRIDGE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeOpenObject(
    JNIEnv *env, jobject self, jstring path);
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeLoadObject(
    JNIEnv *env, jobject self, jlong ptr);
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeAttachAll(
    JNIEnv *env, jobject self, jlong ptr);
JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeDestroyObject(
    JNIEnv *env, jobject self, jlong ptr);
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetMapFd(
    JNIEnv *env, jobject self, jlong objPtr, jstring mapName);
JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapLookup(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint valueSize);
JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapGetNextKey(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint keySize);
JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapDelete(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key);
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetNumPossibleCpus(
    JNIEnv *env, jobject self);
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapBatchLookupAndDelete(
    JNIEnv *env, jobject self,
    jint mapFd, jbyteArray keys, jbyteArray values,
    jint keySize, jint valueSize, jint maxBatch);

#ifdef __cplusplus
}
#endif

#endif
