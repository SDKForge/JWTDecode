package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.data.algorithm.ECDSA256
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA384
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA512
import dev.sdkforge.jwt.decode.data.algorithm.HMAC256
import dev.sdkforge.jwt.decode.data.algorithm.HMAC384
import dev.sdkforge.jwt.decode.data.algorithm.HMAC512
import dev.sdkforge.jwt.decode.data.algorithm.NONE
import dev.sdkforge.jwt.decode.data.algorithm.RSA256
import dev.sdkforge.jwt.decode.data.algorithm.RSA384
import dev.sdkforge.jwt.decode.data.algorithm.RSA512
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import io.mockk.junit4.MockKRule
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import org.junit.Rule

@OptIn(ExperimentalTime::class)
class JWTTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    // Decode
    @Test
    fun shouldDecodeAStringToken() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        JWT.decode(token)
    }

    @Test
    fun shouldDecodeAStringTokenUsingInstance() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        JWT.decode(token)
    }

    // getToken
    @Test
    fun shouldGetStringToken() {
        val token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"
        val jwt = JWT.decode(token)

        assertEquals(token, jwt.token)
    }

    // getToken
    @Test
    fun shouldGetStringTokenUsingInstance() {
        val token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"
        val decodedJWT = JWT.decode(token)

        assertEquals(token, decodedJWT.token)
    }

    // Verify
    @Test
    fun shouldVerifyDecodedToken() {
        val token =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"
        val decodedJWT = JWT.decode(token)
        val key = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA512(key)

        JWT.require(algorithm).build().verify(decodedJWT)
    }

    @Test
    fun shouldAcceptNoneAlgorithm() {
        val token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9."
        val algorithm = Algorithm.NONE

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptHMAC256Algorithm() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"
        val algorithm = Algorithm.HMAC256("secret")

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptHMAC384Algorithm() {
        val token =
            "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw"
        val algorithm = Algorithm.HMAC384("secret")

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptHMAC512Algorithm() {
        val token =
            "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw"
        val algorithm = Algorithm.HMAC512("secret")

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptRSA256Algorithm() {
        val token =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"
        val key = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA256(key)

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptRSA384Algorithm() {
        val token =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"
        val key = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA384(key)

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptRSA512Algorithm() {
        val token =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"
        val key = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA512(key)

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptECDSA256Algorithm() {
        val token =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_256, "EC")
        val algorithm = Algorithm.ECDSA256(key)

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptECDSA384Algorithm() {
        val token =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_384, "EC")
        val algorithm = Algorithm.ECDSA384(key)

        JWT.require(algorithm).build().verify(token)
    }

    @Test
    fun shouldAcceptECDSA512Algorithm() {
        val token =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_512, "EC")
        val algorithm = Algorithm.ECDSA512(key)

        JWT.require(algorithm).build().verify(token)
    }

    // Standard Claims
    @Test
    fun shouldGetAlgorithm() {
        val token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("HS256", jwt.algorithm)
    }

    @Test
    fun shouldGetSignature() {
        val token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ", jwt.signature)
    }

    @Test
    fun shouldGetIssuer() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("John Doe", jwt.issuer)
    }

    @Test
    fun shouldGetSubject() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("Tok3ns", jwt.subject)
    }

    @Test
    fun shouldGetArrayAudience() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals(3, jwt.audience?.size)
        assertTrue(jwt.audience?.contains("Hope") == true)
        assertTrue(jwt.audience?.contains("Travis") == true)
        assertTrue(jwt.audience?.contains("Solomon") == true)
    }

    @Test
    fun shouldGetStringAudience() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals(1, jwt.audience?.size)
        assertTrue(jwt.audience?.contains("Jack Reyes") == true)
    }

    @Test
    fun shouldGetExpirationTime() {
        val seconds = 1477592L
        val mockNow = Instant.fromEpochSeconds(seconds - 1)
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0Nzc1OTJ9.x_ZjkPkKYUV5tdvc0l8go6D_z2kez1MQcOxokXrDc3k"
        val algorithm = Algorithm.HMAC256("secret")
        val verification = JWT.require(algorithm) as JWTVerifier.BaseVerification

        val jwt = verification.build(mockNow).verify(token)

        assertEquals(Instant.fromEpochSeconds(seconds), jwt.expiresAt)
    }

    @Test
    fun shouldGetNotBefore() {
        val seconds: Long = 1477592
        val clock = Instant.fromEpochSeconds(seconds)
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTJ9.mWYSOPoNXstjKbZkKrqgkwPOQWEx3F3gMm6PMcfuJd8"
        val algorithm = Algorithm.HMAC256("secret")
        val verification = JWT.require(algorithm) as JWTVerifier.BaseVerification

        val jwt = verification.build(clock).verify(token)

        assertEquals(Instant.fromEpochSeconds(seconds), jwt.notBefore)
    }

    @Test
    fun shouldGetIssuedAt() {
        val seconds: Long = 1477592
        val clock = Instant.fromEpochSeconds(seconds)
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.5o1CKlLFjKKcddZzoarQ37pq7qZqNPav3sdZ_bsZaD4"
        val algorithm = Algorithm.HMAC256("secret")
        val verification = JWT.require(algorithm) as JWTVerifier.BaseVerification

        val jwt = verification.build(clock).verify(token)

        assertEquals(Instant.fromEpochSeconds(seconds), jwt.issuedAt)
    }

    @Test
    fun shouldGetId() {
        val token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA"
        val algorithm = Algorithm.HMAC256("secret")
        val verification = JWT.require(algorithm) as JWTVerifier.BaseVerification

        val jwt = verification.build().verify(token)

        assertEquals("1234567890", jwt.id)
    }

    @Test
    fun shouldGetContentType() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("awesome", jwt.contentType)
    }

    @Test
    fun shouldGetType() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("JWS", jwt.type)
    }

    @Test
    fun shouldGetKeyId() {
        val token = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleSJ9.e30.von1Vt9tq9cn5ZYdX1f4cf2EE7fUvb5BCBlKOTm9YWs"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertEquals("key", jwt.keyId)
    }

    @Test
    fun shouldGetCustomClaims() {
        val token = "eyJhbGciOiJIUzI1NiIsImlzQWRtaW4iOnRydWV9.eyJpc0FkbWluIjoibm9wZSJ9.YDKBAgUDbh0PkhioDcLNzdQ8c2Gdf_yS6zdEtJQS3F0"
        val algorithm = Algorithm.HMAC256("secret")
        val jwt = JWT.require(algorithm).build().verify(token)

        assertIs<JsonClaim>(jwt.getHeaderClaim("isAdmin"))
        assertEquals(true, jwt.getHeaderClaim("isAdmin").asBoolean())
        assertIs<JsonClaim>(jwt.getClaim("isAdmin"))
        assertEquals("nope", jwt.getClaim("isAdmin").asString())
    }

    // Sign
    @Test
    fun shouldCreateAnEmptyHMAC256SignedToken() {
        val algorithm = Algorithm.HMAC256("secret")
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "HS256").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(algorithm).build()
    }

    @Test
    fun shouldCreateAnEmptyHMAC384SignedToken() {
        val algorithm = Algorithm.HMAC384("secret")
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "HS384").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(algorithm).build()
    }

    @Test
    fun shouldCreateAnEmptyHMAC512SignedToken() {
        val algorithm = Algorithm.HMAC512("secret")
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "HS512").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(algorithm).build()
    }

    @Test
    fun shouldCreateAnEmptyRSA256SignedToken() {
        val privateKey = readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA256(privateKey)
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "RS256").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.RSA256(readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA"))).build()
    }

    @Test
    fun shouldCreateAnEmptyRSA384SignedToken() {
        val privateKey = readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA384(privateKey)
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "RS384").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.RSA384(readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA"))).build()
    }

    @Test
    fun shouldCreateAnEmptyRSA512SignedToken() {
        val privateKey = readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE_RSA, "RSA")
        val algorithm = Algorithm.RSA512(privateKey)
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "RS512").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.RSA512(readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE_RSA, "RSA"))).build()
    }

    @Test
    fun shouldCreateAnEmptyECDSA256SignedToken() {
        val privateKey = readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_EC_256, "EC")
        val algorithm = Algorithm.ECDSA256(privateKey)
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "ES256").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.ECDSA256(readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_256, "EC"))).build()
    }

    @Test
    fun shouldCreateAnEmptyECDSA384SignedToken() {
        val algorithm = Algorithm.ECDSA384(readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_EC_384, "EC"))
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "ES384").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.ECDSA384(readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_384, "EC"))).build()
    }

    @Test
    fun shouldCreateAnEmptyECDSA512SignedToken() {
        val privateKey = readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_EC_512, "EC")
        val algorithm = Algorithm.ECDSA512(privateKey)
        val signed = JWT.create().sign(algorithm)

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.hasEntry("alg", "ES512").matches(headerJson))
        assertTrue(JsonMatcher.hasEntry("typ", "JWT").matches(headerJson))
        assertEquals("e30", parts[1])

        JWT.require(Algorithm.ECDSA512(readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_EC_512, "EC"))).build()
    }

    companion object {
        private const val PUBLIC_KEY_FILE_RSA = "src/androidUnitTest/resources/rsa-public.pem"
        private const val PRIVATE_KEY_FILE_RSA = "src/androidUnitTest/resources/rsa-private.pem"

        private const val PUBLIC_KEY_FILE_EC_256 = "src/androidUnitTest/resources/ec256-key-public.pem"
        private const val PUBLIC_KEY_FILE_EC_384 = "src/androidUnitTest/resources/ec384-key-public.pem"
        private const val PUBLIC_KEY_FILE_EC_512 = "src/androidUnitTest/resources/ec512-key-public.pem"
        private const val PRIVATE_KEY_FILE_EC_256 = "src/androidUnitTest/resources/ec256-key-private.pem"
        private const val PRIVATE_KEY_FILE_EC_384 = "src/androidUnitTest/resources/ec384-key-private.pem"
        private const val PRIVATE_KEY_FILE_EC_512 = "src/androidUnitTest/resources/ec512-key-private.pem"
    }
}
