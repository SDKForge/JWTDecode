package dev.sdkforge.jwt.decode

import dev.sdkforge.jwt.decode.Library.VERSION

/**
 * Library metadata and version information.
 *
 * This object contains the current version of the library
 * and can be used for version checking and compatibility verification.
 *
 * @property VERSION The current version of the library in semantic versioning format
 */
data object Library {
    /**
     * The current version of the library.
     *
     * This follows semantic versioning (MAJOR.MINOR.PATCH) format.
     *
     * @return The version string (e.g., "1.0.0")
     */
    const val VERSION = "0.0.1"
}
