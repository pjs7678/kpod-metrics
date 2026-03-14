plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
}

group = "com.internal"
version = "1.11.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

sourceSets {
    create("bpfGenerator")
}

dependencies {
    // Spring Boot
    implementation(libs.spring.boot.starter.web)
    implementation(libs.spring.boot.starter.actuator)

    // Kotlin
    implementation(libs.kotlin.reflect)
    implementation(libs.kotlinx.coroutines.core)

    // Prometheus metrics
    implementation(libs.micrometer.registry.prometheus)

    // OTLP metrics export (optional at runtime)
    implementation(libs.micrometer.registry.otlp)

    // OpenTelemetry SDK (tracing / span export)
    implementation(libs.opentelemetry.api)
    implementation(libs.opentelemetry.sdk)
    implementation(libs.opentelemetry.exporter.otlp)

    // JSON parsing
    implementation(libs.jackson.module.kotlin)

    // Kubernetes client
    implementation(libs.kubernetes.client)

    // Protobuf (pprof profile format)
    implementation(libs.protobuf.java)

    // eBPF DSL (composite build)
    implementation("dev.ebpf:kotlin-ebpf-dsl")

    // Test
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(kotlin("test"))
    testImplementation(sourceSets["bpfGenerator"].output)
    testImplementation("dev.ebpf:kotlin-ebpf-dsl")

    // bpfGenerator source set
    "bpfGeneratorImplementation"("dev.ebpf:kotlin-ebpf-dsl")
    "bpfGeneratorImplementation"("org.jetbrains.kotlin:kotlin-stdlib")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

val generateBpf = tasks.register<JavaExec>("generateBpf") {
    classpath = sourceSets["bpfGenerator"].runtimeClasspath
    mainClass.set("com.internal.kpodmetrics.bpf.programs.GenerateBpfKt")
    outputs.dir(layout.buildDirectory.dir("generated/bpf"))
    outputs.dir(layout.buildDirectory.dir("generated/kotlin"))
}

sourceSets["main"].kotlin.srcDir(layout.buildDirectory.dir("generated/kotlin"))

tasks.named("compileKotlin") {
    dependsOn(generateBpf)
}
