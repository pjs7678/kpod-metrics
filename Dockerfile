# kpod-metrics/Dockerfile

# Stage 1: Compile eBPF programs
FROM ubuntu:24.04 AS bpf-builder
ARG TARGET_ARCH=arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY bpf/ /build/bpf/

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
    -c /build/bpf/cpu_sched.bpf.c -o /build/bpf/cpu_sched.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
    -c /build/bpf/net.bpf.c -o /build/bpf/net.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
    -c /build/bpf/mem.bpf.c -o /build/bpf/mem.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
    -c /build/bpf/syscall.bpf.c -o /build/bpf/syscall.bpf.o

# Stage 2: Build JNI native library
FROM ubuntu:24.04 AS jni-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make gcc libbpf-dev libelf-dev zlib1g-dev openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64
COPY jni/ /build/jni/
RUN cmake -B /build/jni/build /build/jni && cmake --build /build/jni/build
# Collect runtime shared library dependencies (libbpf is statically linked)
RUN mkdir -p /runtime-libs && \
    cp /usr/lib/aarch64-linux-gnu/libelf*.so* /runtime-libs/ && \
    cp /lib/aarch64-linux-gnu/libz.so* /runtime-libs/

# Stage 3: Build Kotlin application
FROM gradle:8.12-jdk21 AS app-builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
COPY gradle/ gradle/
RUN gradle dependencies --no-daemon
COPY src/ src/
RUN gradle bootJar --no-daemon

# Stage 4: Runtime (noble = Ubuntu 24.04, matches builder GLIBC)
FROM eclipse-temurin:21-jre-noble

COPY --from=bpf-builder /build/bpf/*.bpf.o /app/bpf/
COPY --from=jni-builder /build/jni/build/libkpod_bpf.so /app/lib/
COPY --from=jni-builder /runtime-libs/* /app/lib/
COPY --from=app-builder /build/build/libs/*.jar /app/kpod-metrics.jar

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Xss256k"
ENV LD_LIBRARY_PATH=/app/lib

EXPOSE 9090

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.library.path=/app/lib -jar /app/kpod-metrics.jar"]
