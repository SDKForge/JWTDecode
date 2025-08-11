plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.dokka)
    alias(libs.plugins.build.logic.library.kmp)
    alias(libs.plugins.build.logic.library.android)
    alias(libs.plugins.build.logic.library.publishing)
    alias(libs.plugins.build.logic.binary.validation)
}

kotlin {
    androidLibrary {
        namespace = "dev.sdkforge.jwt.decode.core"
    }

    sourceSets {
        commonMain {
            dependencies {
                // put your multiplatform dependencies here
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}
