import java.io.File

plugins {
    `java-library`
    `maven-publish`
}

group = "dev.securekeypad"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    withSourcesJar()
}

tasks.compileJava {
    options.release.set(11)
    options.encoding = "UTF-8"
}

// The test client uses the Ed25519 / EdEC API (Java 15+); tests run on the JDK that runs Gradle.
tasks.compileTestJava {
    options.release.set(17)
    options.encoding = "UTF-8"
}

// ---- native JNI library (bundles libskp + libsodium + zlib statically) ------------------------------
val osNameRaw = System.getProperty("os.name").lowercase()
val skpOs = when {
    osNameRaw.contains("mac") || osNameRaw.contains("darwin") -> "darwin"
    osNameRaw.contains("win") -> "windows"
    else -> "linux"
}
val archRaw = System.getProperty("os.arch").lowercase()
val skpArch = when (archRaw) {
    "aarch64", "arm64" -> "aarch64"
    "amd64", "x86_64", "x64" -> "x86_64"
    else -> archRaw
}
val nativeLibFile = when (skpOs) {
    "darwin" -> "libskp_jni.dylib"
    "windows" -> "skp_jni.dll"
    else -> "libskp_jni.so"
}

fun findCMake(): String {
    System.getenv("CMAKE")?.let { if (File(it).exists()) return it }
    System.getenv("PATH")?.split(File.pathSeparator)?.forEach { dir ->
        listOf("cmake", "cmake.exe").forEach { name ->
            val f = File(dir, name)
            if (f.isFile) return f.path
        }
    }
    listOf(
        "/opt/homebrew/bin/cmake",
        "/usr/local/bin/cmake",
        "/usr/bin/cmake",
        System.getProperty("user.home") + "/Library/Android/sdk/cmake/3.22.1/bin/cmake",
    ).forEach { if (File(it).isFile) return it }
    throw GradleException("cmake not found: install it or set CMAKE=/path/to/cmake")
}

val cmakeExe = findCMake()
val nativeBuildDir = layout.buildDirectory.dir("native")
val nativeResDir = layout.buildDirectory.dir("native-res")
val jdkHome: String = System.getProperty("java.home")

val configureNative by tasks.registering(Exec::class) {
    group = "build"
    description = "Configures the CMake build of the JNI library and the C core"
    inputs.dir("src/main/c")
    inputs.dir("../../core/src")
    inputs.dir("../../core/include")
    inputs.file("../../core/CMakeLists.txt")
    outputs.file(nativeBuildDir.map { it.file("CMakeCache.txt") })
    commandLine(
        cmakeExe, "-S", file("src/main/c").path, "-B", nativeBuildDir.get().asFile.path,
        "-DCMAKE_BUILD_TYPE=Release", "-DSKP_JAVA_HOME=$jdkHome",
    )
}

val buildNative by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds libskp_jni for the current platform"
    dependsOn(configureNative)
    inputs.dir("src/main/c")
    inputs.dir("../../core/src")
    inputs.dir("../../core/include")
    inputs.dir("../../core/fonts")
    inputs.dir("../../core/third_party")
    outputs.file(nativeBuildDir.map { it.file(nativeLibFile) })
    commandLine(cmakeExe, "--build", nativeBuildDir.get().asFile.path, "--config", "Release", "--target", "skp_jni")
}

val copyNative by tasks.registering(Copy::class) {
    group = "build"
    description = "Places the native library where the jar picks it up as native/<os>-<arch>/"
    dependsOn(buildNative)
    from(nativeBuildDir.map { it.file(nativeLibFile) })
    into(nativeResDir.map { it.dir("native/$skpOs-$skpArch") })
}

sourceSets.main {
    resources.srcDir(nativeResDir)
}

tasks.processResources {
    dependsOn(copyNative)
}

tasks.named<Jar>("sourcesJar") {
    dependsOn(copyNative)
    exclude("native/**")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("secure-keypad server SDK")
                description.set("Server-side SDK for the secure-keypad protocol: per-session shuffled keypads, encrypted coordinates, sealed sessions.")
                url.set("https://github.com/secure-keypad/secure-keypad")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
            }
        }
    }
}
