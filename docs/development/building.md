# Building

## Docker (Recommended)

The build context requires both this repo and [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl) as a sibling directory:

```
parent/
├── kpod-metrics/
└── kotlin-ebpf-dsl/
```

```bash
docker build -f kpod-metrics/Dockerfile -t kpod-metrics:latest .
```

### Multi-Architecture Build

```bash
docker buildx build -f kpod-metrics/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  -t kpod-metrics:latest .
```

## Local Development

Requires JDK 21 and kotlin-ebpf-dsl as a sibling directory:

```bash
./gradlew generateBpf  # Generate BPF C code + Kotlin MapReader classes
./gradlew build         # Compile + test (293 tests)
./gradlew bootJar       # Build executable JAR
```

!!! note
    BPF programs and JNI library must be cross-compiled in a Linux environment. The Dockerfile handles this automatically.

## Build Stages

The 5-stage Dockerfile handles:

| Stage | Purpose | Output |
|-------|---------|--------|
| Codegen | Gradle runs kotlin-ebpf-dsl | Generated `.bpf.c` + Kotlin `MapReader` classes |
| BPF compile | clang compiles C | CO-RE (5.2+) and legacy (4.18+) `.bpf.o` objects |
| JNI build | CMake compiles JNI bridge | `libkpod_bpf.so` |
| App build | Gradle builds Spring Boot | Executable JAR |
| Runtime | Eclipse Temurin JRE 21 | Final minimal image |
