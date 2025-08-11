import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.NativeBuildType
import org.jetbrains.kotlin.konan.target.Family

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.binaryCompatibilityValidator)
    alias(libs.plugins.dokka)
    alias(libs.plugins.build.logic.library.kmp)
    alias(libs.plugins.build.logic.library.android)
    alias(libs.plugins.build.logic.library.publishing)
}

kotlin {
    // export dependencies for iOS
    targets.filterIsInstance<KotlinNativeTarget>()
        .filter { it.konanTarget.family == Family.IOS }
        .forEach { target ->
            NativeBuildType.DEFAULT_BUILD_TYPES.forEach { buildType ->
                target.binaries.getFramework(buildType).apply {
                    export(projects.sharedCore)
                    export(projects.sharedData)
                    export(projects.sharedDi)
                    export(projects.sharedDomain)
                    export(projects.sharedNetwork)
                    export(projects.sharedUi)
                }
            }
        }

    sourceSets {
        commonMain {
            dependencies {
                api(projects.sharedCore)
                api(projects.sharedData)
                api(projects.sharedDi)
                api(projects.sharedDomain)
                api(projects.sharedNetwork)
                api(projects.sharedUi)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}

android {
    namespace = "dev.sdkforge.jwt.decode"
}
