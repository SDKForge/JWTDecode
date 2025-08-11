package dev.sdkforge.jwt.decode.core

/**
 * Platform information interface.
 *
 * This interface provides access to platform-specific information such as
 * the platform name and version. It is implemented differently for each
 * target platform to provide accurate platform details.
 *
 * ## Platform Implementations
 *
 * - **Android**: Returns "Android" with the Android API level
 * - **iOS**: Returns "iOS" or "iPadOS" with the iOS system version
 *
 * @property name The name of the platform (e.g., "Android", "iOS", "iPadOS")
 * @property version The version string of the platform
 */
interface Platform {
    /**
     * The name of the current platform.
     *
     * @return Platform name as a string
     */
    val name: String

    /**
     * The version of the current platform.
     *
     * @return Platform version as a string
     */
    val version: String
}

/**
 * The current platform instance.
 *
 * This expect declaration is implemented differently for each target platform
 * to provide the appropriate platform information.
 *
 * ## Platform-Specific Implementations
 *
 * - **Android**: Returns platform name "Android" and API level as version
 * - **iOS**: Returns system name (iOS/iPadOS) and system version
 *
 * @return A [Platform] instance representing the current platform
 */
expect val currentPlatform: Platform
