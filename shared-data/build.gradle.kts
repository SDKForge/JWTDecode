plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.binaryCompatibilityValidator)
    alias(libs.plugins.dokka)
    alias(libs.plugins.build.logic.library.kmp)
    alias(libs.plugins.build.logic.library.android)
    alias(libs.plugins.build.logic.library.publishing)
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                implementation(project(":shared-domain"))

                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization.json)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
        androidMain {
            dependencies {
                implementation("dev.sdkforge.crypto:crypto-domain-android:0.0.2-SNAPSHOT")
            }
        }
        androidUnitTest {
            dependencies {
                implementation("org.bouncycastle:bcprov-jdk18on:1.82")
                implementation("io.mockk:mockk:1.14.5")
                implementation("net.jodah:concurrentunit:0.4.6")
                implementation("org.hamcrest:hamcrest:3.0")
            }
        }
    }
}

android {
    namespace = "dev.sdkforge.jwt.decode.data"
}
