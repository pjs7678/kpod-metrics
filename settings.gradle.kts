rootProject.name = "kpod-metrics"

// Path to kotlin-ebpf-dsl composite build; override with -PebpfDslPath=/path for Docker builds
val ebpfDslPath: String = providers.gradleProperty("ebpfDslPath")
    .getOrElse("../../kotlin-ebpf-dsl")

includeBuild(ebpfDslPath)
