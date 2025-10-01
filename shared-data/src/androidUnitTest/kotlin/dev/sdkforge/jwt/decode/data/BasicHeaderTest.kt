package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Header
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertIsNot
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

private const val ALGORITHM = "test"

class BasicHeaderTest {

    @Test
    fun shouldHaveUnmodifiableTreeWhenInstantiatedWithNonNullTree() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            tree = mutableMapOf(),
        )

        assertIs<MutableMap<*, *>>((header as JWTHeader).tree)
    }

    @Test
    fun shouldHaveUnmodifiableTreeWhenInstantiatedWithNullTree() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
        )

        assertIsNot<MutableMap<*, *>>((header as JWTHeader).tree)
    }

    @Test
    fun shouldHaveTree() {
        val tree: Map<String, JsonElement> = mapOf(
            "key" to JsonNull,
        )
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            tree = tree,
        )

        assertIsNot<EmptyClaim>(header.getHeaderClaim("key"))
    }

    @Test
    fun shouldGetAlgorithm() {
        val header: Header = JWTHeader(
            algorithm = "HS256",
        )

        assertNotNull(header.algorithm)
        assertEquals("HS256", header.algorithm)
    }

    @Test
    fun shouldGetType() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            type = "jwt",
        )

        assertNotNull(header.type)
        assertEquals("jwt", header.type)
    }

    @Test
    fun shouldGetNullTypeIfMissing() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
        )

        assertNull(header.type)
    }

    @Test
    fun shouldGetContentType() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            contentType = "content",
        )

        assertNotNull(header.contentType)
        assertEquals("content", header.contentType)
    }

    @Test
    fun shouldGetNullContentTypeIfMissing() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
        )

        assertNull(header.contentType)
    }

    @Test
    fun shouldGetKeyId() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            keyId = "key",
        )

        assertNotNull(header.keyId)
        assertEquals("key", header.keyId)
    }

    @Test
    fun shouldGetNullKeyIdIfMissing() {
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
        )

        assertNull(header.keyId)
    }

    @Test
    fun shouldGetExtraClaim() {
        val tree = mapOf<String, JsonElement>(
            "extraClaim" to JsonPrimitive("extraValue"),
        )
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            tree = tree,
        )

        assertIs<JsonClaim>(header.getHeaderClaim("extraClaim"))
        assertEquals("extraValue", header.getHeaderClaim("extraClaim").asString())
    }

    @Test
    fun shouldGetNotNullExtraClaimIfMissing() {
        val tree = mutableMapOf<String, JsonElement>()
        val header: Header = JWTHeader(
            algorithm = ALGORITHM,
            tree = tree,
        )

        assertNotNull(header.getHeaderClaim("missing"))
        assertTrue(header.getHeaderClaim("missing").isMissing)
        assertTrue(!header.getHeaderClaim("missing").isNull)
    }
}
