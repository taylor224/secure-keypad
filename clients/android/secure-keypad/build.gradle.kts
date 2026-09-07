import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

group = "dev.securekeypad"
version = "0.1.0"

android {
    namespace = "dev.securekeypad"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Verified on Maven Central 2026-09-07 (bcprov-jdk18on latest 1.85.2; kotlinx-coroutines-android latest 1.11.0).
    // BouncyCastle's lightweight API gives X25519, Ed25519 verify and ChaCha20-Poly1305 with a caller-chosen
    // nonce on every API level; Tink's fixed-nonce ChaCha20-Poly1305 lives in an internal package only.
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
    // org.json is part of the Android platform; on the JVM the unit tests need the real implementation.
    testImplementation("org.json:json:20250517")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "dev.securekeypad"
            artifactId = "secure-keypad-android"
            version = project.version.toString()
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("secure-keypad Android client")
                description.set("Secure keypad client: server-rendered shuffled keypad, encrypted tap coordinates")
                licenses { license { name.set("Apache-2.0") } }
            }
        }
    }
}
