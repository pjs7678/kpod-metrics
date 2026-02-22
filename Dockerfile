# kpod-metrics/Dockerfile

# Stage 1: Compile eBPF programs
FROM ubuntu:22.04 AS bpf-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-tools-common bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY bpf/ /build/bpf/

# Generate vmlinux.h (will be provided at build time or pre-generated)
# RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /build/bpf/vmlinux.h

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/cpu_sched.bpf.c -o /build/bpf/cpu_sched.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/net.bpf.c -o /build/bpf/net.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/mem.bpf.c -o /build/bpf/mem.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/syscall.bpf.c -o /build/bpf/syscall.bpf.o

# Stage 2: Build JNI native library
FROM ubuntu:22.04 AS jni-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake gcc libbpf-dev libelf-dev zlib1g-dev openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

COPY jni/ /build/jni/
RUN cmake -B /build/jni/build /build/jni && cmake --build /build/jni/build

# Stage 3: Build Kotlin application
FROM gradle:8-jdk21 AS app-builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
COPY gradle/ gradle/
RUN gradle dependencies --no-daemon
COPY src/ src/
RUN gradle bootJar --no-daemon

# Stage 4: Runtime
FROM eclipse-temurin:21-jre-jammy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bpf-builder /build/bpf/*.bpf.o /app/bpf/
COPY --from=jni-builder /build/jni/build/libkpod_bpf.so /app/lib/
COPY --from=app-builder /build/build/libs/*.jar /app/kpod-metrics.jar

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Xss256k"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.library.path=/app/lib -jar /app/kpod-metrics.jar"]
