# Adding a New Collector

Follow these steps to add a new metric collector to kpod-metrics.

## Steps

### 1. Define the BPF Program

Create a new program definition in `src/bpfGenerator/kotlin/.../bpf/programs/`:

```kotlin
val myProgram = ebpfProgram("my_collector") {
    val key = struct("my_key") { u64("cgroup_id") }
    val myMap = hashMap("my_map", key, BpfScalar.U64, maxEntries = 10240)

    tracepoint("subsystem", "event_name") {
        val cgId = getCurrentCgroupId()
        val ptr = mapLookupElem(myMap, cgId)
        ifNonNull(ptr) { atomicIncrement(it) }
    }
}
```

### 2. Create the Collector Class

Create the collector in `src/main/kotlin/.../collector/`:

```kotlin
@Component
class MyCollector(
    private val bpfBridge: BpfBridge,
    private val meterRegistry: MeterRegistry
) : MetricsCollector {

    override fun collect(pods: List<PodInfo>) {
        val entries = bpfBridge.readMap("my_map")
        for ((key, value) in entries) {
            val cgroupId = MyMapReader.MyKeyLayout.decodeCgroupId(key)
            // Register metric with pod labels...
        }
    }
}
```

### 3. Register the Bean

Add the bean to `BpfAutoConfiguration`:

```kotlin
@Bean
@ConditionalOnProperty("kpod.collectors.my-collector", matchIfMissing = true)
fun myCollector(bpfBridge: BpfBridge, registry: MeterRegistry) =
    MyCollector(bpfBridge, registry)
```

### 4. Add to Profile

Update `MetricsProperties` to include the collector in the appropriate profile(s).

### 5. Write Tests

Use `MockK` for mocking and `SimpleMeterRegistry` for metric verification:

```kotlin
class MyCollectorTest {
    private val bpfBridge = mockk<BpfBridge>()
    private val registry = SimpleMeterRegistry()
    private val collector = MyCollector(bpfBridge, registry)

    @Test
    fun `should record metric for pod`() {
        every { bpfBridge.readMap("my_map") } returns mapOf(...)
        collector.collect(listOf(testPod))
        // Assert metrics...
    }
}
```

### 6. Update Dashboard

If the new metric should be visualized, add a panel to the Grafana dashboard JSON.

## Checklist

- [ ] BPF program defined in `src/bpfGenerator/kotlin/`
- [ ] Collector class in `src/main/kotlin/.../collector/`
- [ ] Bean registered in `BpfAutoConfiguration`
- [ ] Added to profile in `MetricsProperties`
- [ ] Unit tests written
- [ ] Grafana dashboard updated (if applicable)
- [ ] Helm schema updated (if new values added)
