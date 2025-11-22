package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Payload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalTime::class)
class PayloadDeserializerTest {

    @Test
    fun shouldNotRemoveKnownPublicClaimsFromTree() {
        val payloadJSON = "{\n" +
            "  \"iss\": \"auth0\",\n" +
            "  \"sub\": \"emails\",\n" +
            "  \"aud\": \"users\",\n" +
            "  \"iat\": 10101010,\n" +
            "  \"exp\": 11111111,\n" +
            "  \"nbf\": 10101011,\n" +
            "  \"jti\": \"idid\",\n" +
            "  \"roles\":\"admin\" \n" +
            "}"

        val payload: Payload = JWTParser.parsePayload(payloadJSON)

        assertEquals("auth0", payload.issuer)
        assertEquals("emails", payload.subject)
        assertTrue(payload.audience?.contains("users") == true)
        assertEquals(10101010L * 1000, payload.issuedAt?.toEpochMilliseconds())
        assertEquals(11111111L * 1000, payload.expiresAt?.toEpochMilliseconds())
        assertEquals(10101011L * 1000, payload.notBefore?.toEpochMilliseconds())
        assertEquals(10101010L, payload.issuedAt?.epochSeconds)
        assertEquals(11111111L, payload.expiresAt?.epochSeconds)
        assertEquals(10101011L, payload.notBefore?.epochSeconds)
        assertEquals("idid", payload.id)

        assertEquals("admin", payload.getClaim("roles").asString())
        assertEquals("auth0", payload.getClaim("iss").asString())
        assertEquals("emails", payload.getClaim("sub").asString())
        assertEquals("users", payload.getClaim("aud").asString())
        assertEquals(10101010.0, payload.getClaim("iat").asDouble())
        assertEquals(11111111.0, payload.getClaim("exp").asDouble())
        assertEquals(10101011.0, payload.getClaim("nbf").asDouble())
        assertEquals("idid", payload.getClaim("jti").asString())
    }
}
