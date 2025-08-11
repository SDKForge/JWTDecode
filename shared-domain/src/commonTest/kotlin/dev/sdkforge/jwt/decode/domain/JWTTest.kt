@file:Suppress("ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

package dev.sdkforge.jwt.decode.domain

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class JWTTest {

    // Exceptions
    @Test
    fun shouldThrowIfLessThan3Parts() {
        assertFailsWith<DecodeException>(
            message = "The token was expected to have 3 parts, but got 2.",
        ) {
            JWT("two.parts")
        }
    }

    @Test
    fun shouldThrowIfMoreThan3Parts() {
        assertFailsWith<DecodeException>(
            message = "The token was expected to have 3 parts, but got 4.",
        ) {
            JWT("this.has.four.parts")
        }
    }

    @Test
    fun shouldThrowIfItsNotBase64Encoded() {
        assertFailsWith<DecodeException>(
            message = "Received bytes didn't correspond to a valid Base64 encoded string.",
        ) {
            JWT("thisIsNot.Base64_Enc.oded")
        }
    }

    @Test
    fun shouldThrowIfPayloadHasInvalidJSONFormat() {
        assertFailsWith<DecodeException>(
            message = "The token's payload had an invalid JSON format.",
        ) {
            JWT("eyJhbGciOiJIUzI1NiJ9.e30ijfe923.XmNK3GpH3Ys_7lyQ")
        }
    }

    // toString
    @Test
    fun shouldGetStringToken() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")

        assertEquals("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ", jwt.toString())
    }

    // Parts
    @Test
    fun shouldGetHeader() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")
        val header = jwt.header

        assertNotNull(header)
        assertEquals("HS256", header["alg"])
    }

    @Test
    fun shouldGetSignature() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ")
        assertEquals("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ", jwt.signature)
    }

    @Test
    fun shouldGetEmptySignature() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.")

        assertEquals("", jwt.signature)
    }

    // Public Claims
    @Test
    fun shouldGetIssuer() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ")
        assertEquals("John Doe", jwt.issuer)
    }

    @Test
    fun shouldGetNullIssuerIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.issuer)
    }

    @Test
    fun shouldGetSubject() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs")

        assertEquals("Tok3ns", jwt.subject)
    }

    @Test
    fun shouldGetNullSubjectIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.subject)
    }

    @Test
    fun shouldGetArrayAudience() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4")

        val audience = jwt.audience

        assertNotNull(audience)
        assertEquals(3, audience.size)
        assertContains(audience, "Hope")
        assertContains(audience, "Travis")
        assertContains(audience, "Solomon")
    }

    @Test
    fun shouldGetStringAudience() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc")

        val audience = jwt.audience

        assertNotNull(audience)
        assertEquals(1, audience.size)
        assertContains(audience, "Jack Reyes")
    }

    @Test
    fun shouldGetEmptyListAudienceIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        val audience = jwt.audience

        assertNotNull(audience)
        assertEquals(emptyList(), audience)
    }

    @Test
    fun shouldDeserializeDatesUsingLong() {
        val jwt = JWT(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjIxNDc0OTM2NDcsIm5iZiI6MjE0NzQ5MzY0NywiZXhwIjoyMTQ3NDkzNjQ3LCJjdG0iOjIxNDc0OTM2NDd9.txmUJ0UCy2pqTFrEgj49eNDQCWUSW_XRMjMaRqcrgLg",
        )

        val seconds: Long = Int.MAX_VALUE + 10000L
        val expectedDate = Instant.fromEpochSeconds(seconds)

        assertEquals(expectedDate, jwt.issuedAt)
        assertEquals(expectedDate, jwt.notBefore)
        assertEquals(expectedDate, jwt.expiresAt)
        assertEquals(expectedDate, jwt.getClaim("ctm").asDate())
    }

    @Test
    fun shouldGetExpirationTime() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOiIxNDc2NzI3MDg2In0.XwZztHlQwnAgmnQvrcWXJloLOUaLZGiY0HOXJCKRaks")
        val expectedDate = Instant.fromEpochSeconds(1476727086L)

        assertNotNull(jwt.expiresAt)
        assertEquals(expectedDate, jwt.expiresAt)
    }

    @Test
    fun shouldGetNullExpirationTimeIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.expiresAt)
    }

    @Test
    fun shouldGetNotBefore() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOiIxNDc2NzI3MDg2In0.pi3Fi3oFiXk5A5AetDdL0hjVx_rt6F5r_YiG6HoCYDw")
        val expectedDate = Instant.fromEpochSeconds(1476727086L)

        assertNotNull(jwt.notBefore)
        assertEquals(expectedDate, jwt.notBefore)
    }

    @Test
    fun shouldGetNullNotBeforeIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.notBefore)
    }

    @Test
    fun shouldGetIssuedAt() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOiIxNDc2NzI3MDg2In0.u6BxwrO7S0sqDY8-1cUOLzU2uejAJBzQQF8g_o5BAgo")

        val expectedDate = Instant.fromEpochSeconds(1476727086L)
        assertNotNull(jwt.issuedAt)
        assertEquals(expectedDate, jwt.issuedAt)
    }

    @Test
    fun shouldGetNullIssuedAtIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.issuedAt)
    }

    @Test
    fun shouldGetId() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA")

        assertEquals("1234567890", jwt.id)
    }

    @Test
    fun shouldGetNullIdIfMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.something")

        assertNull(jwt.id)
    }

    @Test
    fun shouldNotBeDeemedExpiredWithoutDateClaims() {
        val jwt = customTimeJWT(null, null)

        assertFalse { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldNotBeDeemedExpired() {
        val jwt = customTimeJWT(null, Clock.System.now().toEpochMilliseconds() + 2000)

        assertFalse { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldBeDeemedExpired() {
        val jwt = customTimeJWT(null, Clock.System.now().toEpochMilliseconds() - 2000)

        assertTrue { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldNotBeDeemedExpiredByLeeway() {
        val jwt = customTimeJWT(null, Clock.System.now().toEpochMilliseconds() - 1000)

        assertFalse { jwt.isExpired(2.seconds) }
    }

    @Test
    fun shouldBeDeemedExpiredByLeeway() {
        val jwt = customTimeJWT(null, Clock.System.now().toEpochMilliseconds() - 2000)

        assertTrue { jwt.isExpired(1.seconds) }
    }

    @Test
    fun shouldNotBeDeemedFutureIssued() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() - 2000, null)

        assertFalse { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldBeDeemedFutureIssued() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() + 2000, null)

        assertTrue { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldNotBeDeemedFutureIssuedByLeeway() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() + 1000, null)

        assertFalse { jwt.isExpired(2.seconds) }
    }

    @Test
    fun shouldBeDeemedFutureIssuedByLeeway() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() + 2000, null)

        assertTrue { jwt.isExpired(1.seconds) }
    }

    @Test
    fun shouldBeDeemedNotTimeValid() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() + 1000, Clock.System.now().toEpochMilliseconds() - 1000)

        assertTrue { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldBeDeemedTimeValid() {
        val jwt = customTimeJWT(Clock.System.now().toEpochMilliseconds() - 1000, Clock.System.now().toEpochMilliseconds() + 1000)

        assertFalse { jwt.isExpired(0.seconds) }
    }

    @Test
    fun shouldThrowIfLeewayIsNegative() {
        assertFailsWith<IllegalArgumentException>(
            message = "The leeway must be a positive value.",
        ) {
            customTimeJWT(null, null).isExpired(-(1.seconds))
        }
    }

    @Test
    fun shouldNotRemoveKnownPublicClaimsFromTree() {
        val jwt = JWT(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCIsInN1YiI6ImVtYWlscyIsImF1ZCI6InVzZXJzIiwiaWF0IjoxMDEwMTAxMCwiZXhwIjoxMTExMTExMSwibmJmIjoxMDEwMTAxMSwianRpIjoiaWRpZCIsInJvbGVzIjoiYWRtaW4ifQ.jCchxb-mdMTq5EpeVMSQyTp6zSwByKnfl9U-Zc9kg_w",
        )

        assertEquals("auth0", jwt.issuer)
        assertEquals("emails", jwt.subject)
        assertContains(jwt.audience.orEmpty(), "users")

        assertEquals(Instant.fromEpochSeconds(10101010L), jwt.issuedAt)
        assertEquals(Instant.fromEpochSeconds(11111111L), jwt.expiresAt)
        assertEquals(Instant.fromEpochSeconds(10101011L), jwt.notBefore)
        assertEquals("idid", jwt.id)

        assertEquals("admin", jwt.getClaim("roles").asString())
        assertEquals("auth0", jwt.getClaim("iss").asString())
        assertEquals("emails", jwt.getClaim("sub").asString())
        assertEquals("users", jwt.getClaim("aud").asString())
        assertEquals(10101010.0, jwt.getClaim("iat").asDouble())
        assertEquals(11111111.0, jwt.getClaim("exp").asDouble())
        assertEquals(10101011.0, jwt.getClaim("nbf").asDouble())
        assertEquals("idid", jwt.getClaim("jti").asString())
    }

    // Private Claims
    @Test
    fun shouldGetBaseClaimIfClaimIsMissing() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.K17vlwhE8FCMShdl1_65jEYqsQqBOVMPUU9IgG-QlTM")
        assertNotNull(jwt.getClaim("notExisting"))
        assertTrue { jwt.getClaim("notExisting") is ClaimImpl }
        assertTrue { jwt.getClaim("notExisting") is BaseClaim }
    }

    @Test
    fun shouldGetClaim() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifX0.lrU1gZlOdlmTTeZwq0VI-pZx2iV46UWYd5-lCjy6-c4")

        assertNotNull(jwt.getClaim("object"))
        assertTrue { jwt.getClaim("object") is ClaimImpl }
    }

    @Test
    fun shouldGetAllClaims() {
        val jwt =
            JWT("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifSwic3ViIjoiYXV0aDAifQ.U20MgOAV81c54mRelwYDJiLllb5OVwUAtMGn-eUOpTA")
        val claims: Map<String, Claim>? = jwt.claims

        assertNotNull(claims)

        val objectClaim = claims["object"]

        assertNotNull(objectClaim)

        assertTrue { objectClaim is ClaimImpl }

        val extraClaim: Claim = claims["sub"]!!

        assertNotNull(extraClaim)

        assertEquals("auth0", extraClaim.asString())
    }

    @Test
    fun shouldGetEmptyAllClaims() {
        val jwt = JWT("eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo")
        val claims: Map<String, Claim?> = assertNotNull(jwt.claims)

        assertTrue { claims.isEmpty() }
    }

    // Parcelable
    @Test
    fun shouldBeParceled() {
        val jwtOrigin = JWT("eyJhbGciOiJIUzI1NiJ9.e30.K17vlwhE8FCMShdl1_65jEYqsQqBOVMPUU9IgG-QlTM")

//        val bundleOrigin: Bundle = Bundle()
//        bundleOrigin.putParcelable("jwt", jwtOrigin)
//        val parcel: Parcel = Parcel.obtain()
//        bundleOrigin.writeToParcel(parcel, 0)
//
//        //Extract bundle from parcel
//        parcel.setDataPosition(0)
//        val bundleDest: Bundle = parcel.readBundle(JWT::class.java.getClassLoader())
//        val jwtDest: JWT = bundleDest.getParcelable("jwt")
//
//        assertThat(jwtDest, `is`(notNullValue()))
//        assertThat(bundleOrigin, `is`(not(bundleDest)))
//        assertThat(jwtOrigin, `is`(not(jwtDest)))
//        assertThat(jwtOrigin.toString(), `is`(jwtDest.toString()))
    }

    /**
     * Creates a new JWT with custom time claims.
     *
     * @param iatMs iat value in MILLISECONDS
     * @param expMs exp value in MILLISECONDS
     * @return a JWT
     */
    private fun customTimeJWT(iatMs: Long?, expMs: Long?): JWT {
        val header = encodeString("{}")
        val bodyBuilder = StringBuilder("{")
        if (iatMs != null) {
            val iatSeconds = (iatMs / 1000).toLong()
            bodyBuilder.append("\"iat\":\"").append(iatSeconds).append("\"")
        }
        if (expMs != null) {
            if (iatMs != null) {
                bodyBuilder.append(",")
            }
            val expSeconds = (expMs / 1000).toLong()
            bodyBuilder.append("\"exp\":\"").append(expSeconds).append("\"")
        }
        bodyBuilder.append("}")
        val body = encodeString(bodyBuilder.toString())
        val signature = "sign"
        return JWT("$header.$body.$signature")
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encodeString(source: String): String {
        return Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(source.encodeToByteArray())
    }
}
