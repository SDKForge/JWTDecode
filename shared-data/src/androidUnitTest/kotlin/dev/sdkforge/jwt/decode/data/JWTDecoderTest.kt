package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import io.mockk.junit4.MockKRule
import java.nio.charset.StandardCharsets
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import org.junit.Rule

@OptIn(ExperimentalTime::class)
class JWTDecoderTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    @Test
    fun getSubject() {
        val jwt = JWT.decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
        )

        assertNotNull(jwt.subject)
        assertEquals("1234567890", jwt.subject)
    }

    // Exceptions
    @Test
    fun shouldThrowIfTheContentIsNotProperlyEncoded() {
        val t = assertFailsWith<JWTDecodeException> {
            JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciO-corrupted.eyJ0ZXN0IjoxMjN9.sLtFC2rLAzN0-UJ13OLQX6ezNptAQzespaOGwCnpqk")
        }

        assertEquals("The input is not a valid base 64 encoded string.", t.message)
    }

    @Test
    fun shouldThrowIfLessThan3Parts() {
        val t = assertFailsWith<JWTDecodeException> {
            JWT.decode("two.parts")
        }

        assertEquals("The token was expected to have 3 parts, but got 2.", t.message)
    }

    @Test
    fun shouldThrowIfMoreThan3Parts() {
        val t = assertFailsWith<JWTDecodeException> {
            JWT.decode("this.has.four.parts")
        }

        assertEquals("The token was expected to have 3 parts, but got 4.", t.message)
    }

    @Test
    fun shouldThrowIfPayloadHasInvalidJSONFormat() {
        val validJson = "{}"
        val invalidJson = "}{"

        val t = assertFailsWith<JWTDecodeException> {
            customJWT(validJson, invalidJson, "signature")
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }

    @Test
    fun shouldThrowIfHeaderHasInvalidJSONFormat() {
        val validJson = "{}"
        val invalidJson = "}{"

        val t = assertFailsWith<JWTDecodeException> {
            customJWT(invalidJson, validJson, "signature")
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }

    @Test
    fun shouldThrowWhenHeaderNotValidBase64() {
        val jwt = "eyJhbGciOiJub25l+IiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss"

        val t = assertFailsWith<JWTDecodeException> {
            JWT.decode(jwt)
        }

        assertIs<IllegalArgumentException>(t.cause)
    }

    @Test
    fun shouldThrowWhenPayloadNotValidBase64() {
        val jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRo+MCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss"

        val t = assertFailsWith<JWTDecodeException> {
            JWT.decode(jwt)
        }

        assertIs<IllegalArgumentException>(t.cause)
    }

    // Parts
    @Test
    fun shouldGetStringToken() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ", jwt.token)
    }

    @Test
    fun shouldGetHeader() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("eyJhbGciOiJIUzI1NiJ9", jwt.header)
    }

    @Test
    fun shouldGetPayload() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("e30", jwt.payload)
    }

    @Test
    fun shouldGetSignature() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ", jwt.signature)
    }

    // Standard Claims
    @Test
    fun shouldGetIssuer() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ")

        assertEquals("John Doe", jwt.issuer)
    }

    @Test
    fun shouldGetSubject() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs")

        assertEquals("Tok3ns", jwt.subject)
    }

    @Test
    fun shouldGetArrayAudience() {
        val jwt = JWT.decode(
            "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4",
        )

        assertEquals(3, jwt.audience?.size)
        assertTrue(jwt.audience!!.containsAll(listOf("Hope", "Travis", "Solomon")))
    }

    @Test
    fun shouldGetStringAudience() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc")

        assertEquals(1, jwt.audience?.size)
        assertTrue(jwt.audience!!.contains("Jack Reyes"))
    }

    @Test
    fun shouldGetExpirationTime() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.L9dcPHEDQew2u9MkDCORFkfDGcSOsgoPqNY-LUMLEHg")
        val ms = 1476727086L * 1000

        assertEquals(Instant.fromEpochMilliseconds(ms), jwt.expiresAt)
    }

    @Test
    fun shouldGetNotBefore() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0NzY3MjcwODZ9.tkpD3iCPQPVqjnjpDVp2bJMBAgpVCG9ZjlBuMitass0")
        val ms = 1476727086L * 1000

        assertEquals(Instant.fromEpochMilliseconds(ms), jwt.notBefore)
    }

    @Test
    fun shouldGetIssuedAt() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.KPjGoW665E8V5_27Jugab8qSTxLk2cgquhPCBfAP0_w")
        val ms = 1476727086L * 1000

        assertEquals(Instant.fromEpochMilliseconds(ms), jwt.issuedAt)
    }

    @Test
    fun shouldGetId() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA")

        assertEquals("1234567890", jwt.id)
    }

    @Test
    fun shouldGetContentType() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs")

        assertEquals("awesome", jwt.contentType)
    }

    @Test
    fun shouldGetType() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI")

        assertEquals("JWS", jwt.type)
    }

    @Test
    fun shouldGetAlgorithm() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("HS256", jwt.algorithm)
    }

    // Private Claims
    @Test
    fun shouldGetMissingClaimIfClaimDoesNotExist() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.K17vlwhE8FCMShdl1_65jEYqsQqBOVMPUU9IgG-QlTM")

        assertNotNull(jwt.getClaim("notExisting"))
        assertTrue(jwt.getClaim("notExisting").isMissing)
        assertFalse(jwt.getClaim("notExisting").isNull)
    }

    @Test
    fun shouldGetValidClaim() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifX0.lrU1gZlOdlmTTeZwq0VI-pZx2iV46UWYd5-lCjy6-c4")

        assertNotNull(jwt.getClaim("object"))
        assertIs<Claim>(jwt.getClaim("object"))
    }

    @Test
    fun shouldNotGetNullClaimIfClaimIsEmptyObject() {
        val jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnt9fQ.d3nUeeL_69QsrHL0ZWij612LHEQxD8EZg1rNoY3a4aI")

        assertNotNull(jwt.getClaim("object"))
        assertFalse(jwt.getClaim("object").isNull)
    }

    @Test
    fun shouldGetCustomClaimOfTypeInteger() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA"
        val jwt = JWT.decode(token)

        assertEquals(123, jwt.getClaim("name").asInt())
    }

    @Test
    fun shouldGetCustomClaimOfTypeDouble() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA"
        val jwt = JWT.decode(token)

        assertEquals(23.45, jwt.getClaim("name").asDouble())
    }

    @Test
    fun shouldGetCustomClaimOfTypeBoolean() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0"

        val jwt = JWT.decode(token)

        assertTrue(jwt.getClaim("name").asBoolean() == true)
    }

    @Test
    fun shouldGetCustomClaimOfTypeDate() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c"
        val instant = Instant.fromEpochMilliseconds(1478891521000L)
        val jwt = JWT.decode(token)

        assertEquals(instant, jwt.getClaim("name").asInstant())
    }

    @Test
    fun shouldGetCustomClaimOfTypeInstant() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c"
        val instant: Instant? = Instant.fromEpochSeconds(1478891521L)
        val jwt = JWT.decode(token)

        assertEquals(instant, jwt.getClaim("name").asInstant())
    }

    @Test
    fun shouldGetCustomArrayClaimOfTypeString() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA"
        val jwt = JWT.decode(token)

        assertEquals(jwt.getClaim("name").asList(String.serializer()), listOf("text", "123", "true"))
    }

    @Test
    fun shouldGetCustomArrayClaimOfTypeInteger() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE"
        val jwt = JWT.decode(token)

        assertEquals(jwt.getClaim("name").asList(Int.serializer()), listOf(1, 2, 3))
    }

    @Test
    fun shouldGetCustomMapClaim() {
        val token =
            "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InN0cmluZyI6InZhbHVlIiwibnVtYmVyIjoxLCJib29sZWFuIjp0cnVlLCJlbXB0eSI6bnVsbH19.6xkCuYZnu4RA0xZSxlYSYAqzy9JDWsDtIWqSCUZlPt8"
        val jwt = JWT.decode(token)
        val map = jwt.getClaim("name").asObject(MapSerializer(String.serializer(), JsonPrimitive.serializer()))

        assertNotNull(map)
        assertEquals(JsonPrimitive("value"), map["string"])
        assertEquals(JsonPrimitive(1), map["number"])
        assertEquals(JsonPrimitive(true), map["boolean"])
        assertEquals(JsonNull, map["empty"])
    }

    @Test
    fun shouldGetCustomNullClaim() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpudWxsfQ.X4ALHe7uYqEcXWFBnwBUNRKwmwrtDEGZ2aynRYYUx8c"
        val jwt = JWT.decode(token)

        assertTrue(jwt.getClaim("name").isNull)
    }

    @Test
    fun shouldGetListClaim() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbbnVsbCwiaGVsbG8iXX0.SpcuQRBGdTV0ofHdxBSnhWEUsQi89noZUXin2Thwb70"
        val jwt = JWT.decode(token)

        val list: List<String?> = jwt.getClaim("name").asList(String.serializer().nullable)

        assertContains(list, null)
        assertContains(list, "hello")
    }

    @Test
    fun shouldGetAvailableClaims() {
        JWT.decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEyMzQ1Njc4OTAsImlhdCI6MTIzNDU2Nzg5MCwibmJmIjoxMjM0NTY3ODkwLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.2_0nxDPJwOk64U5V5V9pt8U92jTPJbGsHYQ35HYhbdE",
        )
    }

    @Test
    fun shouldSerializeAndDeserialize() {
        val originalJwt = JWT.decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEyMzQ1Njc4OTAsImlhdCI6MTIzNDU2Nzg5MCwibmJmIjoxMjM0NTY3ODkwLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.2_0nxDPJwOk64U5V5V9pt8U92jTPJbGsHYQ35HYhbdE",
        )

        assertEquals(originalJwt.header, originalJwt.header)
        assertEquals(originalJwt.payload, originalJwt.payload)
        assertEquals(originalJwt.signature, originalJwt.signature)
        assertEquals(originalJwt.token, originalJwt.token)
        assertEquals(originalJwt.algorithm, originalJwt.algorithm)
        assertEquals(originalJwt.audience, originalJwt.audience)
        assertEquals(originalJwt.contentType, originalJwt.contentType)
        assertEquals(originalJwt.expiresAt, originalJwt.expiresAt)
        assertEquals(originalJwt.id, originalJwt.id)
        assertEquals(originalJwt.issuedAt, originalJwt.issuedAt)
        assertEquals(originalJwt.issuer, originalJwt.issuer)
        assertEquals(originalJwt.keyId, originalJwt.keyId)
        assertEquals(originalJwt.notBefore, originalJwt.notBefore)
        assertEquals(originalJwt.subject, originalJwt.subject)
        assertEquals(originalJwt.type, originalJwt.type)
        assertEquals(originalJwt.getClaim("extraClaim").asString(), originalJwt.getClaim("extraClaim").asString())
    }

    @Test
    fun shouldDecodeHeaderClaims() {
        val jwt =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImRhdGUiOjE2NDczNTgzMjUsInN0cmluZyI6InN0cmluZyIsImJvb2wiOnRydWUsImRvdWJsZSI6MTIzLjEyMywibGlzdCI6WzE2NDczNTgzMjVdLCJtYXAiOnsiZGF0ZSI6MTY0NzM1ODMyNSwiaW5zdGFudCI6MTY0NzM1ODMyNX0sImludCI6NDIsImxvbmciOjQyMDAwMDAwMDAsImluc3RhbnQiOjE2NDczNTgzMjV9.eyJpYXQiOjE2NDczNjA4ODF9.S2nZDM03ZDvLMeJLWOIqWZ9kmYHZUueyQiIZCCjYNL8"
        val expectedInstant: Instant = Instant.fromEpochSeconds(1647358325)
        val decoded = JWT.decode(jwt)

        assertEquals(expectedInstant, decoded.getHeaderClaim("instant").asInstant())
        assertEquals("string", decoded.getHeaderClaim("string").asString())
        assertTrue(decoded.getHeaderClaim("bool").asBoolean() == true)
        assertEquals(123.123, decoded.getHeaderClaim("double").asDouble())
        assertEquals(42, decoded.getHeaderClaim("int").asInt())
        assertEquals(4200000000L, decoded.getHeaderClaim("long").asLong())

        val headerMap = decoded.getHeaderClaim("map").asObject(MapSerializer(String.serializer(), JsonPrimitive.serializer()))

        assertNotNull(headerMap)
        assertEquals(2, headerMap.size)
        assertEquals(1647358325, headerMap["instant"]?.intOrNull)

        val headerList: List<Any> = decoded.getHeaderClaim("list").asList(JsonPrimitive.serializer())

        assertEquals(1, headerList.size)
        assertContains(headerList, JsonPrimitive(1647358325))
    }

    // Helper Methods
    private fun customJWT(
        jsonHeader: String,
        jsonPayload: String,
        signature: String?,
    ): DecodedJWT {
        val header: String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(jsonHeader.toByteArray(StandardCharsets.UTF_8))
        val body: String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(jsonPayload.toByteArray(StandardCharsets.UTF_8))
        return JWT.decode("$header.$body.$signature")
    }
}
