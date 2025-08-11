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
                    rootProject.allprojects.forEach { project ->
                        if (project.name.startsWith("shared-")) {
                            export(project)
                        }
                    }
                }
            }
        }

    sourceSets {
        commonMain {
            dependencies {
                rootProject.allprojects.forEach { project ->
                    if (project.name.startsWith("shared-")) {
                        api(project)
                    }
                }
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
