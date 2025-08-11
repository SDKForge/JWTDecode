@file:Suppress("ktlint:standard:filename")

package dev.sdkforge.jwt.decode.core

import kotlin.test.Test
import kotlin.test.assertTrue

class CommonPlatformTest {

    @Test
    fun testPlatformDefinition() {
        assertTrue(currentPlatform.name.isNotBlank(), "Platform name is present")
        assertTrue(currentPlatform.version.isNotBlank(), "Platform version is present")
    }
}
