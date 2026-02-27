# kpod-metrics/Dockerfile
#
# Build context: parent directory containing both kpod-metrics/ and kotlin-ebpf-dsl/
#   docker build -f kpod-metrics/Dockerfile -t kpod-metrics .
#
# Build flow:
#   Stage 1 (codegen):    gradle generateBpf -> build/generated/bpf/*.bpf.c
#   Stage 2 (bpf-builder): clang compiles generated .bpf.c -> *.bpf.o
#   Stage 3 (jni-builder):  cmake builds JNI native library
#   Stage 4 (app-builder):  gradle builds Kotlin application (generateBpf is cached)
#   Stage 5 (runtime):      final image

# Stage 1: Generate BPF C code from DSL
FROM gradle:8.12-jdk21 AS codegen
WORKDIR /build
# Copy kotlin-ebpf-dsl (composite build dependency)
COPY kotlin-ebpf-dsl/ /kotlin-ebpf-dsl/
# Copy project build files first for dependency caching
COPY kpod-metrics/build.gradle.kts kpod-metrics/settings.gradle.kts kpod-metrics/gradle.properties ./
COPY kpod-metrics/gradle/ gradle/
RUN gradle -PebpfDslPath=/kotlin-ebpf-dsl dependencies --no-daemon || true
# Copy sources and generate BPF C code
COPY kpod-metrics/src/ src/
RUN gradle -PebpfDslPath=/kotlin-ebpf-dsl -Pkotlin.compiler.execution.strategy=in-process generateBpf --no-daemon

# Stage 2: Compile eBPF programs from generated C code
FROM ubuntu:24.04 AS bpf-builder
ARG TARGET_ARCH=arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# vmlinux.h is a kernel header kept in the repo (not generated)
COPY kpod-metrics/bpf/vmlinux.h /build/bpf/vmlinux.h
COPY kpod-metrics/bpf/compat_vmlinux.h /build/bpf/compat_vmlinux.h
# Copy generated .bpf.c files from codegen stage
COPY --from=codegen /build/build/generated/bpf/ /build/bpf/

# CO-RE build (kernel 5.2+ with BTF) → /build/bpf/core/
RUN mkdir -p /build/bpf/core && \
    for f in /build/bpf/*.bpf.c; do \
      name=$(basename "$f" .bpf.c); \
      clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
        -I/build/bpf -c "$f" -o "/build/bpf/core/${name}.bpf.o"; \
    done

# Legacy build (kernel 4.18-5.1 without BTF) → /build/bpf/legacy/
# Uses compat_vmlinux.h as vmlinux.h — no preserve_access_index, no CO-RE relocations
RUN mkdir -p /build/bpf/legacy /build/bpf/legacy-inc && \
    cp /build/bpf/compat_vmlinux.h /build/bpf/legacy-inc/vmlinux.h && \
    for f in /build/bpf/*.bpf.c; do \
      name=$(basename "$f" .bpf.c); \
      clang -O2 -target bpf -D__TARGET_ARCH_${TARGET_ARCH} \
        -I/build/bpf/legacy-inc -c "$f" -o "/build/bpf/legacy/${name}.bpf.o"; \
    done

# Stage 3: Build JNI native library
FROM ubuntu:24.04 AS jni-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake make gcc libbpf-dev libelf-dev zlib1g-dev openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64
COPY kpod-metrics/jni/ /build/jni/
RUN cmake -B /build/jni/build /build/jni && cmake --build /build/jni/build
# Collect runtime shared library dependencies (libbpf is statically linked)
RUN mkdir -p /runtime-libs && \
    cp /usr/lib/aarch64-linux-gnu/libelf*.so* /runtime-libs/ && \
    cp /lib/aarch64-linux-gnu/libz.so* /runtime-libs/

# Stage 4: Build Kotlin application
FROM gradle:8.12-jdk21 AS app-builder
WORKDIR /build
# Copy kotlin-ebpf-dsl (composite build dependency)
COPY kotlin-ebpf-dsl/ /kotlin-ebpf-dsl/
COPY kpod-metrics/build.gradle.kts kpod-metrics/settings.gradle.kts kpod-metrics/gradle.properties ./
COPY kpod-metrics/gradle/ gradle/
RUN gradle -PebpfDslPath=/kotlin-ebpf-dsl dependencies --no-daemon || true
COPY kpod-metrics/src/ src/
RUN gradle -PebpfDslPath=/kotlin-ebpf-dsl -Pkotlin.compiler.execution.strategy=in-process bootJar --no-daemon

# Stage 5: Runtime (noble = Ubuntu 24.04, matches builder GLIBC)
FROM eclipse-temurin:21-jre-noble

COPY --from=bpf-builder /build/bpf/core/ /app/bpf/core/
COPY --from=bpf-builder /build/bpf/legacy/ /app/bpf/legacy/
COPY --from=jni-builder /build/jni/build/libkpod_bpf.so /app/lib/
COPY --from=jni-builder /runtime-libs/* /app/lib/
COPY --from=app-builder /build/build/libs/*.jar /app/kpod-metrics.jar

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Xss256k"
ENV LD_LIBRARY_PATH=/app/lib

EXPOSE 9090

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.library.path=/app/lib -jar /app/kpod-metrics.jar"]
