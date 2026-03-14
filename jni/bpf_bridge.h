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
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativePerfEventAttach(
    JNIEnv *env, jobject self, jlong objPtr, jstring progName, jint sampleFreq);
JNIEXPORT jlongArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetProgStats(
    JNIEnv *env, jobject self, jlong objPtr);
JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapUpdate(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jbyteArray value, jlong flags);
JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufNew(
    JNIEnv *env, jobject self, jint mapFd);
JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufPoll(
    JNIEnv *env, jobject self, jlong rbPtr, jint maxEvents, jint eventSize);
JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufFree(
    JNIEnv *env, jobject self, jlong rbPtr);

#ifdef __cplusplus
}
#endif

#endif
