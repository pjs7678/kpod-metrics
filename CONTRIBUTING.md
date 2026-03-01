# Contributing to kpod-metrics

## Development Setup

### Prerequisites

- JDK 21
- Gradle 8.12+
- Docker (for building images)
- minikube (for integration/E2E tests)
- clang/llvm (for compiling BPF programs locally)
- [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl) as a sibling directory

### Clone

```bash
git clone https://github.com/pjs7678/kpod-metrics.git
git clone https://github.com/pjs7678/kotlin-ebpf-dsl.git
```

### Build

```bash
cd kpod-metrics
./gradlew build -PebpfDslPath=../kotlin-ebpf-dsl
```

### Run Tests

```bash
./gradlew test -PebpfDslPath=../kotlin-ebpf-dsl
```

### Docker Build

```bash
# From parent directory containing both repos
docker build -f kpod-metrics/Dockerfile -t kpod-metrics .
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `./gradlew test detekt` to verify
4. Run `helm lint helm/kpod-metrics` if modifying Helm templates
5. Push and open a PR against `main`
6. CI must pass (unit tests, detekt, Helm lint)

## Code Style

- Kotlin with Detekt static analysis
- Follow existing patterns in `src/main/kotlin/`
- New collectors should follow the same structure as existing ones in `collector/`
- Tests use MockK for mocking and SimpleMeterRegistry for metric verification

## Adding a New Collector

1. Define the BPF program in `src/bpfGenerator/kotlin/.../bpf/programs/`
2. Create the collector class in `src/main/kotlin/.../collector/`
3. Register the bean in `BpfAutoConfiguration`
4. Add to `MetricsCollectorService` collector list
5. Add to the appropriate profile in `MetricsProperties`
6. Write unit tests
7. Update the Grafana dashboard if applicable
