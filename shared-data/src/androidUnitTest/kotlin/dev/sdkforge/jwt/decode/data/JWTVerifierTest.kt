package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.data.algorithm.HMAC256
import dev.sdkforge.jwt.decode.data.algorithm.HMAC512
import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.AlgorithmMismatchException
import dev.sdkforge.jwt.decode.domain.exception.IncorrectClaimException
import dev.sdkforge.jwt.decode.domain.exception.MissingClaimException
import dev.sdkforge.jwt.decode.domain.exception.TokenExpiredException
import io.mockk.junit4.MockKRule
import io.mockk.mockk
import java.util.Collections.singletonMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.datetime.LocalDate
import kotlinx.datetime.Month
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import org.junit.Rule

@OptIn(ExperimentalTime::class)
class JWTVerifierTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    private val mockNow: Instant = Instant.fromEpochSeconds(1477592)
    private val mockOneSecondEarlier: Instant = mockNow - 1.seconds
    private val mockOneSecondLater: Instant = mockNow + 1.seconds

    @Test
    fun shouldThrowWhenAlgorithmDoesntMatchTheTokensAlgorithm() {
        val verifier = JWTVerifier
            .init(Algorithm.HMAC512("secret"))
            .build() as JWTVerifier

        val t = assertFailsWith<AlgorithmMismatchException> {
            verifier.verify("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho")
        }

        assertEquals("The provided Algorithm doesn't match the one defined in the JWT's Header.", t.message)
    }

    @Test
    fun shouldValidateIssuer() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withIssuer("auth0")
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateMultipleIssuers() {
        val auth0Token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"
        val otherIssuerToken =
            "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJvdGhlcklzc3VlciJ9.k4BCOJJl-c0_Y-49VD_mtt-u0QABKSV5i3W-RKc74co"

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withIssuer("otherIssuer", "auth0")
            .build() as JWTVerifier

        verifier.verify(auth0Token)
        verifier.verify(otherIssuerToken)
    }

    @Test
    fun shouldThrowOnInvalidIssuer() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("invalid")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'iss' value doesn't match the required issuer.", t.message)
        assertEquals(Claim.Companion.Registered.ISSUER, t.claimName)
        assertEquals("auth0", t.claim?.asString())
    }

    @Test
    fun shouldThrowOnNullIssuer() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOm51bGx9.OoiCLipSfflWxkFX2rytvtwEiJ8eAL0opkdXY_ap0qA"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'iss' value doesn't match the required issuer.", t.message)
        assertEquals(Claim.Companion.Registered.ISSUER, t.claimName)
        assertEquals(true, t.claim?.isNull)
    }

    @Test
    fun shouldThrowOnMissingIssuer() {
        val jwt = JWTCreator.init()
            .sign(Algorithm.HMAC256("secret"))

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("nope")
                .build()
                .verify(jwt)
        }

        assertEquals("The Claim 'iss' is not present in the JWT.", t.message)
        assertEquals(Claim.Companion.Registered.ISSUER, t.claimName)
    }

    @Test
    fun shouldValidateSubject() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withSubject("1234567890")
            .build()
            .verify(token)
    }

    @Test
    fun shouldThrowOnInvalidSubject() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("invalid")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'sub' value doesn't match the required one.", t.message)
        assertEquals(Claim.Companion.Registered.SUBJECT, t.claimName)
        assertEquals(1234567890L, t.claim?.asLong())
    }

    @Test
    fun shouldAcceptAudienceWhenWithAudienceContainsAll() {
        // Token 'aud': ["Mark"]
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNYXJrIn0.xWB6czYI0XObbVhLAxe55TwChWZg7zO08RxONWU2iY4"
        // Token 'aud': ["Mark", "David"]
        val tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19.6WfbIt8m61f9WlCYIQn5CThvw4UNyC66qrPaoinfssw"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience("Mark")
            .build()
            .verify(token)

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience("Mark", "David")
            .build()
            .verify(tokenArr)
    }

    @Test
    fun shouldAllowWithAnyOfAudienceVerificationToOverrideWithAudience() {
        // Token 'aud' = ["Mark", "David", "John"]
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("Mark", "Jim")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAnyOfAudience("Mark", "Jim")
            .build()
            .verify(token)
    }

    @Test
    fun shouldAllowWithAudienceVerificationToOverrideWithAnyOfAudience() {
        // Token 'aud' = ["Mark", "David", "John"]
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("Jim")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience("Mark").build().verify(token)
    }

    @Test
    fun shouldAcceptAudienceWhenWithAudienceAndPartialExpected() {
        // Token 'aud' = ["Mark", "David", "John"]
        val tokenArr =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience("John")
            .build()
            .verify(tokenArr)
    }

    @Test
    fun shouldAcceptAudienceWhenAnyOfAudienceAndAllContained() {
        // Token 'aud' = ["Mark", "David", "John"]
        val tokenArr =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAnyOfAudience("Mark", "David", "John")
            .build()
            .verify(tokenArr)
    }

    @Test
    fun shouldThrowWhenAudienceHasNoneOfExpectedAnyOfAudience() {
        // Token 'aud' = ["Mark", "David", "John"]
        val tokenArr =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("Joe", "Jim")
                .build()
                .verify(tokenArr)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)
        assertEquals(Claim.Companion.Registered.AUDIENCE, t.claimName)
        assertTrue { t.claim.toString().contains("Mark") }
        assertTrue { t.claim.toString().contains("David") }
        assertTrue { t.claim.toString().contains("John") }
    }

    @Test
    fun shouldThrowWhenAudienceClaimDoesNotContainAllExpected() {
        // Token 'aud' = ["Mark", "David", "John"]
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("Mark", "Joe")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)
        assertEquals(Claim.Companion.Registered.AUDIENCE, t.claimName)
        assertTrue { t.claim.toString().contains("Mark") }
        assertTrue { t.claim.toString().contains("David") }
        assertTrue { t.claim.toString().contains("John") }
    }

    @Test
    fun shouldThrowWhenAudienceClaimIsNull() {
        // Token 'aud': null
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("nope")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)
        assertEquals(Claim.Companion.Registered.AUDIENCE, t.claimName)
        assertTrue(t.claim?.isNull == true)
    }

    @Test
    fun shouldThrowWhenAudienceClaimIsMissing() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I"

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("nope")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' is not present in the JWT.", t.message)
        assertEquals("aud", t.claimName)
    }

    @Test
    fun shouldThrowWhenAudienceClaimIsNullWithAnAudience() {
        // Token 'aud': [null]
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbbnVsbF19.2cBf7FbkX52h8Vmjnl1DY1PYe_J_YP0KsyeoeYmuca8"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("nope")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)
        assertEquals(Claim.Companion.Registered.AUDIENCE, t.claimName)
        assertTrue { t.claim?.asList(JsonElement.serializer())[0] is JsonNull }
    }

    @Test
    fun shouldThrowWhenExpectedEmptyList() {
        // Token 'aud': 'wide audience'
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ3aWRlIGF1ZGllbmNlIn0.c9anq03XepcuEKWEVsPk9cck0sIIfrT6hHbBsCar49o"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience(*emptyArray<String>())
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'aud' value doesn't contain the required audience.", t.message)
        assertEquals(Claim.Companion.Registered.AUDIENCE, t.claimName)
        assertEquals("wide audience", t.claim?.asString())
    }

    @Test
    fun shouldNotReplaceWhenMultipleChecksAreAdded() {
        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience()
            .withAnyOfAudience()
            .build() as JWTVerifier

        assertEquals(5, verifier.expectedChecks.size)
    }

    @Test
    fun shouldThrowWhenExpectedArrayClaimIsMissing() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcnJheSI6WzEsMiwzXX0.wKNFBcMdwIpdF9rXRxvexrzSM6umgSFqRO1WZj992YM"

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("missing", 1, 2, 3)
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'missing' is not present in the JWT.", t.message)
        assertEquals("missing", t.claimName)
    }

    @Test
    fun shouldThrowWhenExpectedClaimIsMissing() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbSI6InRleHQifQ.aZ27Ze35VvTqxpaSIK5ZcnYHr4SrvANlUbDR8fw9qsQ"

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("missing", "text")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'missing' is not present in the JWT.", t.message)
        assertEquals("missing", t.claimName)
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValueOfTypeString() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", "value")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertEquals(listOf("something"), t.claim?.asList(String.serializer()))
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValueOfTypeInteger() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 123)
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertTrue { t.claim.toString().contains("something") }
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValueOfTypeDouble() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 23.45)
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertTrue { t.claim.toString().contains("something") }
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValueOfTypeBoolean() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", true)
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertTrue { t.claim.toString().contains("something") }
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValueOfTypeDate() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", LocalDate(year = 1999, month = Month.JANUARY, day = 1))
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertTrue { t.claim.toString().contains("something") }
    }

    @Test
    fun shouldThrowOnInvalidCustomClaimValue() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", "check")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'name' value doesn't match the required one.", t.message)
        assertEquals("name", t.claimName)
        assertTrue { t.claim.toString().contains("something") }
    }

    @Test
    fun shouldValidateCustomClaimOfTypeString() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmFsdWUifQ.Jki8pvw6KGbxpMinufrgo6RDL1cu7AtNMJYVh6t-_cE"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", "value")
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomClaimOfTypeInteger() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", 123)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomClaimOfTypeLong() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc2MDB9.km-IwQ5IDnTZFmuJzhSgvjTzGkn_Z5X29g4nAuVC56I"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", 922337203685477600L)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomClaimOfTypeDouble() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", 23.45)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomClaimOfTypeBoolean() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", true)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomClaimOfTypeDate() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c"
        val date = Instant.fromEpochMilliseconds(1478891521123L)

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", date)
            .build()
            .verify(token)
    }

    @Test
    fun shouldNotRemoveCustomClaimOfTypeDateWhenNull() {
        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("name", Instant.DISTANT_FUTURE)
            .build() as JWTVerifier

        assertEquals(4, verifier.expectedChecks.size)
    }

    @Test
    fun shouldValidateCustomArrayClaimOfTypeString() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withArrayClaim("name", "text", "123", "true")
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomArrayClaimOfTypeInteger() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withArrayClaim("name", 1, 2, 3)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomArrayClaimOfTypeLong() {
        val token =
            "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbNTAwMDAwMDAwMDAxLDUwMDAwMDAwMDAwMiw1MDAwMDAwMDAwMDNdfQ.vzV7S0gbV9ZAVxChuIt4XZuSVTxMH536rFmoHzxmayM"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withArrayClaim("name", 500000000001L, 500000000002L, 500000000003L)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomArrayClaimOfTypeLongWhenValueIsInteger() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withArrayClaim("name", 1L, 2L, 3L)
            .build()
            .verify(token)
    }

    @Test
    fun shouldValidateCustomArrayClaimOfTypeLongWhenValueIsIntegerAndLong() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSw1MDAwMDAwMDAwMDIsNTAwMDAwMDAwMDAzXX0.PQjb2rPPpYjM2sItZEzZcjS2YbfPCp6xksTSPjpjTQA"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withArrayClaim("name", 1L, 500000000002L, 500000000003L)
            .build()
            .verify(token)
    }

    // Generic Delta
    @Test
    fun shouldAddDefaultLeewayToDateClaims() {
        val algorithm = mockk<Algorithm>()
        val verification = JWTVerifier.init(algorithm) as JWTVerifier.BaseVerification

        verification.build()

        assertEquals(0L, verification.getLeewayFor(Claim.Companion.Registered.ISSUED_AT))
        assertEquals(0L, verification.getLeewayFor(Claim.Companion.Registered.EXPIRES_AT))
        assertEquals(0L, verification.getLeewayFor(Claim.Companion.Registered.NOT_BEFORE))
    }

    @Test
    fun shouldAddCustomLeewayToDateClaims() {
        val algorithm = mockk<Algorithm>()
        val verification = JWTVerifier.init(algorithm) as JWTVerifier.BaseVerification

        verification
            .acceptLeeway(1234L)
            .build() as JWTVerifier

        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.ISSUED_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.EXPIRES_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.NOT_BEFORE))
    }

    @Test
    fun shouldOverrideDefaultIssuedAtLeeway() {
        val algorithm = mockk<Algorithm>()
        val verification = JWTVerifier.init(algorithm) as JWTVerifier.BaseVerification

        verification
            .acceptLeeway(1234L)
            .acceptIssuedAt(9999L)
            .build() as JWTVerifier

        assertEquals(9999L, verification.getLeewayFor(Claim.Companion.Registered.ISSUED_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.EXPIRES_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.NOT_BEFORE))
    }

    @Test
    fun shouldOverrideDefaultExpiresAtLeeway() {
        val algorithm = mockk<Algorithm>()
        val verification = JWTVerifier.init(algorithm) as JWTVerifier.BaseVerification

        verification
            .acceptLeeway(1234L)
            .acceptExpiresAt(9999L)
            .build() as JWTVerifier

        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.ISSUED_AT))
        assertEquals(9999L, verification.getLeewayFor(Claim.Companion.Registered.EXPIRES_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.NOT_BEFORE))
    }

    @Test
    fun shouldOverrideDefaultNotBeforeLeeway() {
        val algorithm = mockk<Algorithm>()
        val verification = JWTVerifier.init(algorithm) as JWTVerifier.BaseVerification

        verification
            .acceptLeeway(1234L)
            .acceptNotBefore(9999L)
            .build() as JWTVerifier

        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.ISSUED_AT))
        assertEquals(1234L, verification.getLeewayFor(Claim.Companion.Registered.EXPIRES_AT))
        assertEquals(9999L, verification.getLeewayFor(Claim.Companion.Registered.NOT_BEFORE))
    }

    @Test
    fun shouldThrowOnNegativeCustomLeeway() {
        val algorithm = mockk<Algorithm>()

        val t = assertFailsWith<IllegalArgumentException> {
            JWTVerifier.init(algorithm)
                .acceptLeeway(-1)
        }

        assertEquals("Leeway value can't be negative.", t.message)
    }

    // Expires At
    @Test
    fun shouldValidateExpiresAtWithLeeway() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")).acceptExpiresAt(2) as JWTVerifier.BaseVerification

        verification
            .build(mockOneSecondLater)
            .verify(token)
    }

    @Test
    fun shouldValidateExpiresAtIfPresent() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        verification
            .build(mockOneSecondEarlier)
            .verify(token)
    }

    @Test
    fun shouldThrowWhenExpiresAtIsNow() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        // exp must be > now
        val t = assertFailsWith<TokenExpiredException> {
            verification
                .build(mockNow)
                .verify(token)
        }

        assertEquals("The Token has expired on 1970-01-18T02:26:32Z.", t.message)
        assertEquals(Instant.fromEpochSeconds(1477592L), t.expiredOn)
    }

    @Test
    fun shouldThrowOnInvalidExpiresAtIfPresent() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        val t = assertFailsWith<TokenExpiredException> {
            verification
                .build(mockOneSecondLater)
                .verify(token)
        }

        assertEquals("The Token has expired on 1970-01-18T02:26:32Z.", t.message)
        assertEquals(Instant.fromEpochSeconds(1477592L), t.expiredOn)
    }

    @Test
    fun shouldThrowOnNegativeExpiresAtLeeway() {
        val algorithm = mockk<Algorithm>()

        val t = assertFailsWith<IllegalArgumentException> {
            JWTVerifier.init(algorithm)
                .acceptExpiresAt(-1)
        }

        assertEquals("Leeway value can't be negative.", t.message)
    }

    // Not before
    @Test
    fun shouldValidateNotBeforeWithLeeway() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")).acceptNotBefore(2) as JWTVerifier.BaseVerification

        verification
            .build(mockOneSecondEarlier)
            .verify(token)
    }

    @Test
    fun shouldThrowOnInvalidNotBeforeIfPresent() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        val t = assertFailsWith<IncorrectClaimException> {
            verification
                .build(mockOneSecondEarlier)
                .verify(token)
        }

        assertEquals("The Token can't be used before 1970-01-18T02:26:32Z.", t.message)
        assertEquals(Claim.Companion.Registered.NOT_BEFORE, t.claimName)
        assertEquals(1477592L, t.claim?.asLong())
    }

    @Test
    fun shouldValidateNotBeforeIfPresent() {
        val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTN9.f4zVV0TbbTG5xxDjSoGZ320JIMchGoQCWrnT5MyQdT0"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        verification
            .build(mockOneSecondLater)
            .verify(token)
    }

    @Test
    fun shouldAcceptNotBeforeEqualToNow() {
        val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTJ9.71XBtRmkAa4iKnyhbS4NPW-Xr26eAVAdHZgmupS7a5o"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        verification
            .build(mockNow)
            .verify(token)
    }

    @Test
    fun shouldThrowOnNegativeNotBeforeLeeway() {
        val algorithm = mockk<Algorithm>()

        val t = assertFailsWith<IllegalArgumentException> {
            JWTVerifier.init(algorithm)
                .acceptNotBefore(-1)
        }

        assertEquals("Leeway value can't be negative.", t.message)
    }

    // Issued At with future date
    @Test
    fun shouldThrowOnFutureIssuedAt() {
        val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        val t = assertFailsWith<IncorrectClaimException> {
            verification.build(mockOneSecondEarlier).verify(token)
        }

        assertEquals("The Token can't be used before 1970-01-18T02:26:32Z.", t.message)
        assertEquals(Claim.Companion.Registered.ISSUED_AT, t.claimName)
        assertEquals(1477592L, t.claim?.asLong())
    }

    // Issued At with future date and ignore flag
    @Test
    fun shouldSkipIssuedAtVerificationWhenFlagIsPassed() {
        val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        verification.ignoreIssuedAt()

        verification.build(mockOneSecondEarlier).verify(token)
    }

    @Test
    fun shouldThrowOnInvalidIssuedAtIfPresent() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        val t = assertFailsWith<IncorrectClaimException> {
            verification
                .build(mockOneSecondEarlier)
                .verify(token)
        }

        assertEquals("The Token can't be used before 1970-01-18T02:26:32Z.", t.message)
        assertEquals(Claim.Companion.Registered.ISSUED_AT, t.claimName)
        assertEquals(1477592L, t.claim?.asLong())
    }

    @Test
    fun shouldOverrideAcceptIssuedAtWhenIgnoreIssuedAtFlagPassedAndSkipTheVerification() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo"

        val verification = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .acceptIssuedAt(1)
            .ignoreIssuedAt() as JWTVerifier.BaseVerification

        verification
            .build(mockOneSecondEarlier)
            .verify(token)
    }

    @Test
    fun shouldValidateIssuedAtIfPresent() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo"
        val verification = JWTVerifier.init(Algorithm.HMAC256("secret")) as JWTVerifier.BaseVerification

        verification
            .build(mockNow)
            .verify(token)
    }

    @Test
    fun shouldThrowOnNegativeIssuedAtLeeway() {
        val algorithm = mockk<Algorithm>()

        val t = assertFailsWith<IllegalArgumentException> {
            JWTVerifier.init(algorithm)
                .acceptIssuedAt(-1)
        }

        assertEquals("Leeway value can't be negative.", t.message)
    }

    @Test
    fun shouldValidateJWTId() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4"

        JWTVerifier
            .init(Algorithm.HMAC256("secret"))
            .withJWTId("jwt_id_123")
            .build()
            .verify(token)
    }

    @Test
    fun shouldThrowOnInvalidJWTId() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("invalid")
                .build()
                .verify(token)
        }

        assertEquals("The Claim 'jti' value doesn't match the required one.", t.message)
        assertEquals("jti", t.claimName)
        assertEquals("jwt_id_123", t.claim?.asString())
    }

    @Test
    fun shouldNotRemoveClaimWhenPassingNull() {
        val algorithm = mockk<Algorithm>()
        var verifier = JWTVerifier.init(algorithm)
            .withIssuer("iss")
            .build() as JWTVerifier

        assertEquals(4, verifier.expectedChecks.size)

        verifier = JWTVerifier.init(algorithm)
            .withIssuer("iss")
            .build() as JWTVerifier

        assertEquals(4, verifier.expectedChecks.size)
    }

    @Test
    fun shouldNotRemoveIssuerWhenPassingNullReference() {
        val algorithm = mockk<Algorithm>()
        var verifier = JWTVerifier.init(algorithm).build() as JWTVerifier

        assertEquals(3, verifier.expectedChecks.size)

        verifier = JWTVerifier.init(algorithm).build() as JWTVerifier

        assertEquals(3, verifier.expectedChecks.size)

        verifier = JWTVerifier.init(algorithm).withIssuer().build() as JWTVerifier

        assertEquals(4, verifier.expectedChecks.size)

        JWTVerifier.init(algorithm)
            .withIssuer("  ")
            .build() as JWTVerifier
    }

    @Test
    fun shouldSkipClaimValidationsIfNoClaimsRequired() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .build()
            .verify(token)
    }

    @Test
    fun shouldThrowWhenVerifyingClaimPresenceButClaimNotPresent() {
        val jwt = JWTCreator.init()
            .withClaim("custom", "")
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("missing")
            .build() as JWTVerifier

        val t = assertFailsWith<MissingClaimException> {
            verifier.verify(jwt)
        }

        assertEquals("The Claim 'missing' is not present in the JWT.", t.message)
        assertEquals("missing", t.claimName)
    }

    @Test
    fun shouldVerifyStringClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", "")
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyBooleanClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", true)
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyIntegerClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", 123)
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyLongClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", 922337203685477600L)
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyDoubleClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", 12.34)
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyListClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", mutableListOf("item"))
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyMapClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("custom", singletonMap("key", "value"))
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("custom")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldVerifyStandardClaimPresence() {
        val jwt = JWTCreator.init()
            .withClaim("aud", "any value")
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaimPresence("aud")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldSuccessfullyVerifyClaimWithPredicate() {
        val jwt = JWTCreator.init()
            .withClaim("claimName", "claimValue")
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("claimName", { claim, decodedJWT -> "claimValue" == claim.asString() })
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldThrowWhenPredicateReturnsFalse() {
        val jwt = JWTCreator.init()
            .withClaim("claimName", "claimValue")
            .sign(Algorithm.HMAC256("secret"))

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("claimName", { claim, decodedJWT -> "nope" == claim.asString() })
                .build()
                .verify(jwt)
        }

        assertEquals("The Claim 'claimName' value doesn't match the required one.", t.message)
        assertEquals("claimName", t.claimName)
        assertEquals("claimValue", t.claim?.asString())
    }

    @Test
    fun shouldNotRemovePredicateCheckForNull() {
        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withClaim("claimName", { claim, decodedJWT -> "nope" == claim.asString() })
            .build() as JWTVerifier

        assertEquals(4, verifier.expectedChecks.size)
    }

    @Test
    fun shouldSuccessfullyVerifyClaimWithNull() {
        val jwt = JWTCreator.init()
            .withNullClaim("claimName")
            .sign(Algorithm.HMAC256("secret"))

        val verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withNullClaim("claimName")
            .build() as JWTVerifier

        verifier.verify(jwt)
    }

    @Test
    fun shouldThrowWhenNullClaimHasValue() {
        val jwt = JWTCreator.init()
            .withClaim("claimName", "value")
            .sign(Algorithm.HMAC256("secret"))

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withNullClaim("claimName")
                .build()
                .verify(jwt)
        }

        assertEquals("The Claim 'claimName' value doesn't match the required one.", t.message)
        assertEquals("claimName", t.claimName)
        assertEquals("value", t.claim?.asString())
    }

    @Test
    fun shouldThrowWhenNullClaimIsMissing() {
        val jwt = JWTCreator.init()
            .withClaim("claimName", "value")
            .sign(Algorithm.HMAC256("secret"))

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withNullClaim("anotherClaimName")
                .build()
                .verify(jwt)
        }

        assertEquals("The Claim 'anotherClaimName' is not present in the JWT.", t.message)
        assertEquals("anotherClaimName", t.claimName)
    }

    @Test
    fun shouldCheckForNullValuesForSubject() {
        // sub = null
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOm51bGx9.y5brmQQ05OYwVvlTg83njUrz6tfpdyWNh17LHU6DxmI"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .build()
            .verify(token)
    }

    @Test
    fun shouldCheckForNullValuesInIssuer() {
        // iss = null
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOm51bGx9.OoiCLipSfflWxkFX2rytvtwEiJ8eAL0opkdXY_ap0qA"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withIssuer()
            .build()
            .verify(token)
    }

    @Test
    fun shouldCheckForNullValuesInJwtId() {
        // jti = null
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOm51bGx9.z_MDyl8uPGH0q0jeB54wbYt3bwKXamU_3MO8LofGvZs"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .build()
            .verify(token)
    }

    @Test
    fun shouldCheckForNullValuesInCustomClaims() {
        // jti = null
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOm51bGx9.inAuN3Q9UZ6WgbB63O43B1ero2MTqnfzzumr_5qYIls"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .build()
            .verify(token)
    }

    @Test
    fun shouldCheckForNullValuesForAudience() {
        // aud = null
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI"

        JWTVerifier.init(Algorithm.HMAC256("secret"))
            .withAudience()
            .withAnyOfAudience()
            .build()
            .verify(token)
    }

    @Test
    fun shouldCheckForClaimPresenceEvenForNormalClaimChecks() {
        val token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI"

        val t = assertFailsWith<MissingClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("custom", true)
                .build()
                .verify(token)
        }

        assertEquals("custom", t.claimName)
    }

    @Test
    fun shouldCheckForWrongLongClaim() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOjF9.00btiK0sv8pQ2T-hOr9GC5x2osi7--Bsk4pS5cTikqQ"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("custom", 2L)
                .build()
                .verify(token)
        }

        assertEquals("custom", t.claimName)
        assertEquals(1L, t.claim?.asLong())
    }

    @Test
    fun shouldCheckForWrongLongArrayClaim() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("custom", 2L)
                .build()
                .verify(token)
        }

        assertEquals("custom", t.claimName)
    }

    @Test
    fun shouldCheckForWrongStringArrayClaim() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("custom", "2L")
                .build()
                .verify(token)
        }

        assertEquals("custom", t.claimName)
    }

    @Test
    fun shouldCheckForWrongIntegerArrayClaim() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0"

        val t = assertFailsWith<IncorrectClaimException> {
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("custom", 2)
                .build()
                .verify(token)
        }

        assertEquals("custom", t.claimName)
    }
}
