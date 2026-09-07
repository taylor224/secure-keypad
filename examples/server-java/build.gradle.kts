plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("dev.securekeypad:skp-server:0.1.0")
}

tasks.compileJava {
    options.release.set(11)
    options.encoding = "UTF-8"
}

application {
    mainClass.set("dev.securekeypad.example.ExampleServer")
}
