# kpod-metrics 개발기: Kubernetes를 위한 eBPF 기반 Pod 메트릭 수집기

Kubernetes는 Pod가 *요청한 것*을 알려줍니다. kpod-metrics는 커널 수준에서 *실제로 무슨 일이 일어났는지*를 알려줍니다.

표준 Kubernetes 모니터링은 metrics-server를 통해 CPU와 메모리 사용량을 제공합니다. 하지만 Pod가 느려졌을 때, 이것만으로는 부족합니다. CPU 실행 큐에서 대기 중이었나? TCP 재전송이 발생했나? 메이저 페이지 폴트가 일어났나? 시스템콜 지연이 있었나? 이런 질문에 답하려면 커널 수준의 가시성이 필요합니다 -- 바로 eBPF가 필요한 이유입니다.

kpod-metrics는 Linux 커널 트레이스포인트에 eBPF 프로그램을 부착하고 Pod별 성능 메트릭을 Prometheus로 내보내는 DaemonSet입니다. eBPF 이벤트 트레이싱과 cgroup 파일시스템 읽기를 결합하여 스케줄링 지연부터 디스크 I/O까지 Pod 동작의 전체 그림을 제공합니다.

## 문제 정의

프로덕션에서 레이턴시 스파이크를 디버깅하는 상황을 생각해 봅시다. Grafana 대시보드에서 CPU 사용률은 40% -- 리밋보다 훨씬 낮습니다. 메모리도 정상입니다. 애플리케이션 로그에도 특이 사항이 없습니다. 그런데 p99 레이턴시가 두 배로 뛰었습니다.

원인은 다음 중 하나일 수 있습니다:
- **CPU 실행 큐 경합**: 노드의 다른 Pod들이 타임 슬라이스를 소비하고 있어서 내 Pod가 대기 중
- **TCP 재전송**: 네트워크 패킷이 드롭되어 재전송되고 있으며, 재전송당 200ms 이상 추가
- **메이저 페이지 폴트**: 노드의 메모리 압박으로 커널이 디스크에서 메모리를 페이징 중
- **느린 시스템콜**: 파일시스템 `read()`가 I/O에 블로킹되거나, `connect()`가 타임아웃

이 중 어떤 것도 표준 Kubernetes 메트릭에 나타나지 않습니다. 노드에 SSH로 접속해서 `perf`, `bpftrace`, `strace`를 실행하고, 출력을 특정 Pod와 연관 짓는 작업이 필요합니다. kpod-metrics는 이 전체 과정을 자동화합니다.

## 아키텍처

kpod-metrics는 DaemonSet으로 배포됩니다 -- 노드당 하나의 Pod. 각 인스턴스는:

1. **4개의 eBPF 프로그램**을 libbpf에 대한 JNI 브릿지를 통해 커널에 로드
2. 노드 범위의 Kubernetes 인포머를 통해 **Pod 생명주기를 감시**
3. **30초마다 메트릭 수집** -- BPF 맵 배치 읽기와 cgroup 파일 읽기
4. 포트 9090으로 **Prometheus에 내보내기**

```
┌──────────────────────────────────────────────┐
│  kpod-metrics Pod (Spring Boot + JDK 21)     │
│                                               │
│  Collectors (가상 스레드로 병렬 실행)           │
│  ├── eBPF: CPU, Network, Memory, Syscall     │
│  └── Cgroup: DiskIO, Interface, Filesystem   │
│                                               │
│  PodWatcher ──► CgroupResolver               │
│  (K8s 인포머)    (cgroup ID → Pod 메타데이터)  │
│                                               │
│  Prometheus :9090/actuator/prometheus         │
└────────────┬─────────────────────────────────┘
             │ JNI
┌────────────▼─────────────────────────────────┐
│  Linux Kernel                                 │
│  ├── cpu_sched.bpf.o  (sched_switch/wakeup)  │
│  ├── net.bpf.o        (tcp_sendmsg/recvmsg)  │
│  ├── mem.bpf.o        (oom_kill/mm_fault)     │
│  └── syscall.bpf.o    (sys_enter/sys_exit)    │
└───────────────────────────────────────────────┘
```

기술 스택은 Java 21 가상 스레드를 사용하는 Spring Boot 3.4 위의 Kotlin 2.1입니다. eBPF 프로그램은 C로 작성되고, CO-RE(Compile Once, Run Everywhere)로 한 번 컴파일된 후, libbpf에 대한 JNI 브릿지를 통해 런타임에 로드됩니다.

## 측정 항목

### eBPF 메트릭 (커널 이벤트 트레이싱)

**CPU 스케줄링** -- `sched_wakeup`과 `sched_switch` 트레이스포인트에 부착합니다. 태스크가 깨어나면 타임스탬프를 기록하고, CPU에 스케줄링되면 델타를 계산합니다. 이를 통해 실행 큐 지연 시간 -- Pod가 CPU 시간을 얼마나 기다렸는지 알 수 있습니다:

```c
SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &pid);
    if (tsp) {
        __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
        // cgroup_id를 키로 히스토그램에 기록
        __u32 slot = log2l(delta_ns);
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->sum_ns, delta_ns);
    }
}
```

지연 시간 분포는 커널 내에서 log2 히스토그램 버킷을 사용해 구축됩니다. 원자적 `__sync_fetch_and_add` 연산으로 락 없이 여러 CPU에서 안전하게 동시 업데이트할 수 있습니다.

**네트워크** -- 5개의 부착 지점이 TCP 생명주기를 다룹니다: 처리량을 위한 `tcp_sendmsg`와 `tcp_recvmsg`, 재전송을 위한 `tcp_retransmit_skb`, 연결 추적을 위한 `inet_sock_set_state`, RTT 측정을 위한 `tcp_probe`.

**메모리** -- `oom/mark_victim` 트레이스포인트는 커널이 OOM 킬 대상을 선택할 때 발동합니다. `handle_mm_fault`에 대한 kprobe는 메이저 페이지 폴트를 포착합니다.

**시스템콜** -- `sys_enter`와 `sys_exit`에 대한 raw 트레이스포인트로 시스템콜별 지연 시간, 오류율, 호출 횟수를 측정합니다. 오버헤드를 제한하기 위해 추적 대상 시스템콜만 측정합니다 (설정 가능, 기본 10개).

### Cgroup 메트릭 (파일시스템 읽기)

디스크 I/O, 네트워크 인터페이스 통계, 파일시스템 사용량에는 eBPF가 과합니다. 이들은 이미 cgroup v2 컨트롤러와 `/proc`을 통해 커널이 노출하고 있습니다. kpod-metrics는 이를 직접 읽습니다:

- **디스크 I/O** -- `io.stat`에서 장치별 read/write 바이트 및 오퍼레이션 수
- **인터페이스 네트워크** -- `/proc/<pid>/net/dev`에서 인터페이스별 rx/tx 바이트, 패킷, 오류, 드롭
- **파일시스템** -- `/proc/<pid>/mounts` + `statvfs`에서 마운트별 용량, 사용량, 가용 공간

## 핵심 설계 결정

### Cgroup ID를 범용 키로 사용

모든 BPF 맵은 `cgroup_id` -- Pod의 cgroup 디렉토리의 inode 번호 -- 를 키로 사용합니다. eBPF 프로그램이 발동하면 (예: `tcp_sendmsg` 호출 시), `bpf_get_current_cgroup_id()`를 호출하여 이벤트를 트리거한 프로세스의 cgroup을 가져옵니다. 이것이 Kubernetes Pod에 직접 매핑됩니다.

`CgroupResolver`는 cgroup ID에서 Pod 메타데이터 (네임스페이스, Pod 이름, 컨테이너 이름)로의 매핑을 유지합니다. PodWatcher가 Kubernetes API를 통해 새 Pod를 발견하면, `/proc`을 스캔하여 해당 Pod의 컨테이너에 속하는 프로세스를 찾고, cgroup 경로를 해석하여 디렉토리의 inode 번호를 읽습니다:

```kotlin
val attrs = Files.readAttributes(cgroupPath, BasicFileAttributes::class.java)
val fileKey = attrs.fileKey()?.toString()  // "(dev=XXX,ino=YYY)"
val inode = Regex("ino=(\\d+)").find(fileKey)?.groupValues?.get(1)?.toLong()
// 이 inode가 bpf_get_current_cgroup_id()가 반환하는 cgroup_id와 동일
```

### 스냅앤리셋과 배치 오퍼레이션

매 수집 주기마다 BPF 맵의 모든 엔트리를 읽고 0으로 리셋해야 합니다. 단순한 방식 -- 키 순회, 각 값 조회, 각 키 삭제 -- 은 맵당 3N번의 커널 경계 통과가 필요합니다.

kpod-metrics는 모든 엔트리를 원자적으로 읽고 삭제하는 단일 시스템콜인 `bpf_map_lookup_and_delete_batch`를 사용합니다:

```kotlin
fun mapBatchLookupAndDelete(
    mapFd: Int, keySize: Int, valueSize: Int, maxEntries: Int
): List<Pair<ByteArray, ByteArray>> {
    val keysArray = ByteArray(maxEntries * keySize)
    val valuesArray = ByteArray(maxEntries * valueSize)
    val count = nativeMapBatchLookupAndDelete(
        mapFd, keysArray, valuesArray, keySize, valueSize, maxEntries
    )
    if (count == -2) return legacyLookupAndDelete(mapFd, keySize, valueSize)
    // 결과 파싱...
}
```

커널이 배치 오퍼레이션을 지원하지 않는 경우 (5.6 미만), 레거시 순회-조회-삭제 경로로 자동 폴백합니다.

### 메트릭용 LRU 맵

7개의 메트릭 맵 모두 `BPF_MAP_TYPE_HASH` 대신 `BPF_MAP_TYPE_LRU_HASH`를 사용합니다. 표준 해시 맵은 꽉 차면 조용히 실패합니다 -- `bpf_map_update_elem`이 에러를 반환하지만 아무런 표시 없이 데이터를 잃게 됩니다. LRU 맵은 가장 오래 사용되지 않은 엔트리를 자동으로 퇴거시켜 새 엔트리를 위한 공간을 만듭니다.

이것은 우리가 연구한 모든 주요 eBPF 프로젝트에서 사용하는 패턴입니다: Kepler, Tetragon, Inspektor Gadget, Beyla, Coroot 모두 메트릭/캐시 맵에 LRU를 사용합니다.

임시 태스크별 맵 (예: `sched_wakeup`과 `sched_switch` 사이에 타임스탬프를 저장하는 `wakeup_ts`)은 표준 해시 맵으로 유지합니다 -- LRU는 아직 필요한 엔트리를 퇴거시킬 수 있기 때문입니다.

### BPF 맵 헬스 메트릭

BPF 맵의 공간이 부족하면 업데이트가 조용히 실패합니다. 데이터 손실 전에 이를 감지하기 위해, 각 BPF 프로그램이 자체적으로 CPU별 배열 카운터를 사용하여 맵 건강 상태를 추적합니다:

```c
#define STATS_INC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, 1); \
} while(0)

int err = bpf_map_update_elem(&ctx_switches, &key, &val, BPF_ANY);
if (err) {
    STATS_INC(ctx_switches_stats, MAP_STAT_UPDATE_ERRORS);
} else {
    STATS_INC(ctx_switches_stats, MAP_STAT_ENTRIES);
}
```

이들은 Prometheus 메트릭 (`kpod.bpf.map.entries`, `kpod.bpf.map.update.errors.total`, `kpod.bpf.map.capacity`)으로 내보내져, 운영자가 맵 용량 임계치에 대한 알림을 설정할 수 있습니다.

### 삭제된 Pod 유예 캐시

Pod가 삭제되면, 진행 중인 BPF 이벤트가 여전히 해당 cgroup ID를 참조할 수 있습니다. 유예 기간이 없으면 마지막 메트릭들이 "unknown"으로 귀속됩니다. `CgroupResolver`는 삭제된 Pod를 5초 TTL의 유예 캐시로 이동시킵니다:

```kotlin
fun onPodDeleted(cgroupId: Long) {
    val podInfo = cache.remove(cgroupId) ?: return
    graceCache[cgroupId] = GraceCacheEntry(podInfo, Instant.now())
}

fun resolve(cgroupId: Long): PodInfo? =
    cache[cgroupId] ?: graceCache[cgroupId]?.podInfo
```

유예 캐시는 대규모 롤링 배포 시 무한 성장을 방지하기 위해 10,000개 엔트리로 제한되며 LRU 퇴거 방식을 사용합니다.

### 병렬 수집을 위한 가상 스레드

모든 수집기가 Java 21 가상 스레드를 사용하여 병렬로 실행됩니다:

```kotlin
@Scheduled(fixedDelayString = "\${kpod.poll-interval:30000}")
fun collect() = runBlocking(vtDispatcher) {
    (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
        launch {
            collectFn()
        }
    }.joinAll()
}
```

각 수집기는 JNI 호출이나 파일 I/O에서 블로킹되지만, 가상 스레드 덕분에 비용이 적습니다 -- 플랫폼 스레드가 대기하며 묶여 있지 않습니다. 노드에 100개 Pod가 있어도 수집 주기는 500-1000ms에 완료됩니다.

## CO-RE: 한 번 컴파일, 어디서나 실행

eBPF 프로그램은 BPF 바이트코드 형식을 타겟으로 Clang으로 컴파일됩니다:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
    -c cpu_sched.bpf.c -o cpu_sched.bpf.o
```

커널의 BTF(BPF Type Format) 데이터에서 생성된 180,000줄짜리 헤더인 `vmlinux.h`를 포함합니다. `preserve_access_index` 속성은 LLVM에게 오프셋을 하드코딩하는 대신 구조체 필드 접근 패턴을 기록하도록 지시합니다:

```c
#pragma clang attribute push (
    __attribute__((preserve_access_index)), apply_to = record)
```

로드 시점에 libbpf는 실행 중인 커널의 BTF를 `/sys/kernel/btf/vmlinux`에서 읽고, 컴파일된 프로그램의 기대치와 비교한 뒤, 올바른 필드 오프셋으로 바이트코드를 패치합니다. 동일한 `.bpf.o` 파일이 재컴파일 없이 커널 버전 5.8부터 6.x까지 동작합니다.

## 설정 프로필

모든 배포에 모든 메트릭이 필요하지는 않습니다. 세 가지 프로필로 가시성과 오버헤드 사이의 트레이드오프를 조절합니다:

| | minimal | standard | comprehensive |
|---|:---:|:---:|:---:|
| CPU 스케줄링 | yes | yes | yes |
| 네트워크 TCP | - | yes | yes |
| 메모리 이벤트 | 일부 | yes | yes |
| 시스템콜 트레이싱 | - | - | yes |
| 디스크 I/O | yes | yes | yes |
| 인터페이스 네트워크 | - | yes | yes |
| 파일시스템 | - | yes | yes |
| **Pod당 시계열 수** | ~20 | ~39 | ~69 |

`standard` 프로필에서 노드당 100개 Pod 기준, ~3,900개 시계열 -- Prometheus가 충분히 처리할 수 있는 범위입니다.

## 확장성

kpod-metrics는 대규모 클러스터를 위해 설계되었습니다. 각 DaemonSet Pod는 독립적으로 동작합니다:

- **BPF 맵**: 맵당 10,240개 엔트리 (LRU), 일반적인 노드의 ~100-200개 cgroup ID보다 훨씬 큼
- **API 서버**: 노드 범위 인포머 (`spec.nodeName` 필드 셀렉터) -- 클러스터 전체가 아닌 노드당 하나의 워치
- **수집**: 배치 JNI 호출로 커널 경계 통과를 사이클당 맵당 ~1회로 줄임
- **메모리**: 256Mi 요청 / 512Mi 리밋으로 100개 Pod를 넉넉히 처리
- **커널 오버헤드**: 모든 BPF 맵 합쳐서 노드당 ~15-20 MB

**1,000개 노드에 100,000개 Pod** 규모까지 아키텍처를 검증했습니다. 이 규모에서의 주요 제약은 Prometheus 카디널리티입니다 -- 400만 시계열 이하를 유지하려면 `standard` 프로필 (`comprehensive` 아닌)을 사용하세요.

## 오픈소스에서 배운 것들

구현에는 6개 주요 eBPF 프로젝트의 패턴이 반영되어 있습니다:

- **Kepler** (CNCF): LRU 해시 맵, 배치 맵 오퍼레이션
- **Tetragon** (Cilium): 맵별 헬스 메트릭 (`map_entries`, `map_errors`)
- **Inspektor Gadget**: 배치 조회-삭제, 삭제된 Pod에 대한 2초 유예 캐시
- **Beyla** (Grafana): 메트릭 집계용 LRU 맵
- **Pixie** (New Relic): 커널 내 히스토그램 집계
- **Coroot**: Cgroup 우선 Pod 귀속 패턴

가장 큰 교훈: **BPF 맵을 계측하라**. 맵 통계를 추가하기 전에는 맵이 용량에 근접하고 있는지 알 방법이 없었습니다. 관측가능성에서 조용한 데이터 손실은 최악의 장애 모드입니다.

## 시작하기

Helm으로 배포:

```bash
helm install kpod-metrics ./helm/kpod-metrics \
    --namespace kpod-metrics --create-namespace
```

메트릭이 흐르고 있는지 확인:

```bash
kubectl -n kpod-metrics port-forward ds/kpod-metrics 9090:9090
curl -s localhost:9090/actuator/prometheus | grep kpod
```

다음과 같은 메트릭이 나타납니다:

```
kpod_cpu_runqueue_latency_seconds_sum{namespace="default",pod="api-server-xyz",container="api",node="worker-1"} 0.0025
kpod_net_tcp_retransmits_total{namespace="default",pod="api-server-xyz",container="api",node="worker-1"} 3.0
kpod_mem_oom_kills_total{namespace="default",pod="cache-abc",container="redis",node="worker-1"} 1.0
```

요구 사항: BTF가 활성화된 Linux 커널 5.8+, cgroup v2, Kubernetes 1.19+.

## 앞으로의 계획

- **GPU 메트릭**: eBPF 기반 GPU 활용률 추적 (NVIDIA/AMD)
- **Grafana 대시보드**: 일반적인 디버깅 워크플로우를 위한 기본 제공 대시보드
- **알림 규칙**: 일반적인 장애 패턴 (OOM 추세, 재전송 스파이크, 실행 큐 포화)에 대한 PrometheusRule 템플릿
- **OpenTelemetry 내보내기**: Prometheus pull과 함께 OTLP push 지원

프로젝트는 [github.com/pjs7678/kpod-metrics](https://github.com/pjs7678/kpod-metrics)에서 오픈소스로 공개되어 있습니다.
