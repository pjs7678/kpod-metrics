# BPF Code Generation

The build process generates BPF C code and Kotlin MapReader classes from the DSL definitions.

## Running Code Generation

```bash
./gradlew generateBpf
```

This produces:

- `build/generated/bpf/*.bpf.c` — kernel-side C programs
- `build/generated/kotlin/*MapReader.kt` — type-safe map deserialization classes

## Build Pipeline

The 5-stage Dockerfile handles the full pipeline:

1. **Codegen** — Gradle runs kotlin-ebpf-dsl to generate BPF C code and Kotlin MapReader classes
2. **BPF compile** — clang compiles generated `.bpf.c` into both CO-RE (5.2+) and legacy (4.18+) `.bpf.o` objects
3. **JNI build** — CMake compiles the JNI bridge (`libkpod_bpf.so`) against libbpf
4. **App build** — Gradle builds the Spring Boot executable JAR
5. **Runtime** — Eclipse Temurin JRE 21, minimal image with compiled artifacts

## Generated Artifacts in Image

```
/app/
├── bpf/
│   ├── core/     # CO-RE objects (kernel 5.2+)
│   └── legacy/   # Legacy fallback (kernel 4.18+)
├── lib/
│   └── libkpod_bpf.so  # JNI bridge
└── app.jar       # Spring Boot application
```

## MapReader Usage

Collectors use generated `MapReader` layout classes instead of manual `ByteBuffer` parsing:

```kotlin
// Before (manual — error-prone)
val cgroupId = ByteBuffer.wrap(keyBytes)
    .order(ByteOrder.LITTLE_ENDIAN).long

// After (generated — type-safe)
val cgroupId = MemMapReader.CounterKeyLayout
    .decodeCgroupId(keyBytes)
```
