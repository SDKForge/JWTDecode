package dev.sdkforge.jwt.decode.core

import platform.UIKit.UIDevice

/**
 * iOS platform implementation.
 *
 * This actual implementation provides iOS-specific platform information.
 * It uses the UIKit framework's UIDevice to retrieve the current iOS
 * system name and version.
 *
 * ## Implementation Details
 *
 * - **Name**: Returns the iOS system name from `UIDevice.currentDevice.systemName`
 * - **Version**: Returns the iOS system version from `UIDevice.currentDevice.systemVersion`
 *
 * ## Platform Variations
 *
 * The system name may vary depending on the device:
 * - **iPhone**: Returns "iOS"
 * - **iPad**: Returns "iPadOS" (on newer versions)
 * - **Other Apple devices**: May return other system identifiers
 *
 * @return A [Platform] instance with iOS-specific information
 */
actual val currentPlatform: Platform = object : Platform {
    /**
     * The iOS system name.
     *
     * @return The iOS system name (e.g., "iOS", "iPadOS")
     */
    override val name: String get() = UIDevice.currentDevice.systemName

    /**
     * The iOS system version.
     *
     * @return The iOS system version (e.g., "16.5.1")
     */
    override val version: String get() = UIDevice.currentDevice.systemVersion
}
