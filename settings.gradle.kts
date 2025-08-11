@file:Suppress("UnstableApiUsage")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    includeBuild("build-logic")

    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        maven {
            name = "Maven Central Snapshots"
            setUrl("https://central.sonatype.com/repository/maven-snapshots/")
            content { includeGroupByRegex("^dev\\.sdkforge\\.(.+)\$") }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)

    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        maven {
            name = "Maven Central Snapshots"
            setUrl("https://central.sonatype.com/repository/maven-snapshots/")
            content { includeGroupByRegex("^dev\\.sdkforge\\.(.+)\$") }
        }
        mavenCentral()
    }
}

rootProject.name = "SDKForge-JWTDecode"

include(":app-android")
include(":app-shared")
include(":shared")
include(":shared-core")
include(":shared-domain")

include(":internal-ktlint")
// uncomment if it's needed for development
// include(":shared-template")
// include(":internal-benchmark")
