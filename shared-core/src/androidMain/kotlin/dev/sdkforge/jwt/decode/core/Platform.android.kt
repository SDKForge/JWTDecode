package dev.sdkforge.jwt.decode.core

/**
 * Android platform implementation.
 *
 * This actual implementation provides Android-specific platform information.
 * It uses the Android Build API to retrieve the current Android API level
 * as the version information.
 *
 * ## Implementation Details
 *
 * - **Name**: Returns "Android" as the platform identifier
 * - **Version**: Returns the Android API level from `android.os.Build.VERSION.SDK_INT`
 *
 * @return A [Platform] instance with Android-specific information
 */
actual val currentPlatform: Platform = object : Platform {
    /**
     * The Android platform name.
     *
     * @return Always returns "Android"
     */
    override val name: String get() = "Android"

    /**
     * The Android API level.
     *
     * @return The Android SDK_INT as a string (e.g., "33" for API level 33)
     */
    override val version: String get() = android.os.Build.VERSION.SDK_INT.toString()
}
