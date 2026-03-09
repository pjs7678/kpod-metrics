# kpod-metrics

## eBPF Program Policy

All eBPF programs MUST be implemented using kotlin-ebpf-dsl (`src/bpfGenerator/`). Do NOT write hand-written `.bpf.c` files in `bpf/`.

- New BPF programs: define in `src/bpfGenerator/kotlin/.../bpf/programs/` using the DSL
- Existing hand-written programs (`bpf/cpu_profile.bpf.c`, `bpf/tcp_peer.bpf.c`): migrate to DSL when modified
- Use `preamble()` for macros/defines and functions that don't reference DSL-generated structs
- Use `postamble()` for helper functions that reference struct types (emitted after struct/map definitions)
- Use `raw()` escape hatch for complex C that the DSL can't express (pointer chasing, nested loops)
- DNS/HTTP programs emit C-only (no Kotlin MapReader) via `GenerateBpf.kt` — their collectors use raw JNI bridge

## Build

- Requires sibling `kotlin-ebpf-dsl/` directory
- `docker build -f kpod-metrics/Dockerfile -t kpod-metrics .` from parent dir
- Local: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew -PebpfDslPath=<path-to-kotlin-ebpf-dsl> test`

## Workflow

- Always use feature branches + PRs for changes (never push directly to main)
