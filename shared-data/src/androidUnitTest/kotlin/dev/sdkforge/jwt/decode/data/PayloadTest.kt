package dev.sdkforge.jwt.decode.data.impl

import dev.sdkforge.jwt.decode.data.JWTPayload
import dev.sdkforge.jwt.decode.data.JsonClaim
import dev.sdkforge.jwt.decode.domain.Payload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Before

@OptIn(ExperimentalTime::class)
class PayloadTest {

    private var payload: Payload? = null
    private val expiresAt: Instant = Clock.System.now().plus(10.seconds)
    private val notBefore: Instant = Clock.System.now()
    private val issuedAt: Instant = Clock.System.now()

    @Before
    fun setUp() {
        val tree = mapOf<String, JsonElement>(
            "extraClaim" to JsonPrimitive("extraValue"),
        )

        payload = JWTPayload(
            issuer = "issuer",
            subject = "subject",
            expiresAt = expiresAt,
            notBefore = notBefore,
            issuedAt = issuedAt,
            id = "jwtId",
            audience = listOf("audience"),
            tree = tree,
        )
    }

    @Test
    fun shouldHaveUnmodifiableTree() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertTrue { (payload as JWTPayload).tree !is MutableMap }
    }

    @Test
    fun shouldHaveUnmodifiableAudience() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = emptyList(),
        )

        assertTrue { (payload as JWTPayload).audience !is MutableList }
    }

    @Test
    fun shouldGetIssuer() {
        assertEquals("issuer", payload?.issuer)
    }

    @Test
    fun shouldGetNullIssuerIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.issuer)
    }

    @Test
    fun shouldGetSubject() {
        assertEquals("subject", payload?.subject)
    }

    @Test
    fun shouldGetNullSubjectIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.subject)
    }

    @Test
    fun shouldGetAudience() {
        assertEquals(1, payload?.audience?.size)
        assertTrue(payload?.audience?.contains("audience") == true)
    }

    @Test
    fun shouldGetNullAudienceIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.audience)
    }

    @Test
    fun shouldGetExpiresAt() {
        assertEquals(expiresAt, payload?.expiresAt)
    }

    @Test
    fun shouldGetNullExpiresAtIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.expiresAt)
    }

    @Test
    fun shouldGetNotBefore() {
        assertEquals(notBefore, payload?.notBefore)
    }

    @Test
    fun shouldGetNullNotBeforeIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.notBefore)
    }

    @Test
    fun shouldGetIssuedAt() {
        assertEquals(issuedAt, payload?.issuedAt)
    }

    @Test
    fun shouldGetNullIssuedAtIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.issuedAt)
    }

    @Test
    fun shouldGetJWTId() {
        assertEquals("jwtId", payload?.id)
    }

    @Test
    fun shouldGetNullJWTIdIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNull(payload.id)
    }

    @Test
    fun shouldGetExtraClaim() {
        val claim = payload?.getClaim("extraClaim")

        assertIs<JsonClaim>(claim)
        assertEquals("extraValue", claim.asString())
    }

    @Test
    fun shouldGetNotNullExtraClaimIfMissing() {
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = emptyMap(),
        )

        assertNotNull(payload.getClaim("missing"))
        assertTrue(payload.getClaim("missing").isMissing)
        assertFalse(payload.getClaim("missing").isNull)
    }

    @Test
    fun shouldGetClaims() {
        val tree: Map<String, JsonElement> = mutableMapOf(
            "extraClaim" to JsonPrimitive("extraValue"),
            "sub" to JsonPrimitive("auth0"),
        )
        val payload: Payload = JWTPayload(
            issuer = null,
            subject = null,
            expiresAt = null,
            notBefore = null,
            issuedAt = null,
            id = null,
            audience = null,
            tree = tree,
        )

        val claims: Map<String, JsonElement> = (payload as JWTPayload).tree

        assertNotNull(claims)
        assertNotNull(claims["extraClaim"])
        assertNotNull(claims["sub"])
    }
}
