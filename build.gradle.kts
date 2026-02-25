plugins {
    id("org.springframework.boot") version "3.4.3"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("jvm") version "2.1.10"
    kotlin("plugin.spring") version "2.1.10"
}

group = "com.internal"
version = "0.1.0-SNAPSHOT"

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
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    // Kotlin
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")

    // Prometheus metrics
    implementation("io.micrometer:micrometer-registry-prometheus")

    // JSON parsing
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // Kubernetes client
    implementation("io.fabric8:kubernetes-client:7.1.0")

    // eBPF DSL (composite build)
    implementation("dev.ebpf:kotlin-ebpf-dsl")

    // Test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.mockk:mockk:1.13.16")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.1")
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
