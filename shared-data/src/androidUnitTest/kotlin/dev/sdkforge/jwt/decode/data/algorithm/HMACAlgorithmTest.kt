package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.jwt.decode.data.JWT
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import io.mockk.every
import io.mockk.junit4.MockKRule
import io.mockk.mockkStatic
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Assert.assertArrayEquals
import org.junit.Rule

class HMACAlgorithmTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    // Verify
    @Test
    fun shouldGetStringBytes() {
        val text = "abcdef123456!@#$%^"
        val expectedBytes = text.toByteArray()

        assertArrayEquals(expectedBytes, HMACAlgorithm.getSecretBytes(text))
    }

    @Test
    fun shouldCopyTheReceivedSecretArray() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"
        val secretArray = "secret".toByteArray()

        val algorithmString = Algorithm.HMAC256(secretArray) as HMACAlgorithm

        val decoded: DecodedJWT = JWT.decode(jwt)

        algorithmString.verify(decoded)

        secretArray[0] = secretArray[1]

        algorithmString.verify(decoded)
    }

    @Test
    fun shouldPassHMAC256Verification() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        val algorithmString = Algorithm.HMAC256("secret") as HMACAlgorithm
        val algorithmBytes = Algorithm.HMAC256("secret".toByteArray()) as HMACAlgorithm

        val decoded: DecodedJWT = JWT.decode(jwt)

        algorithmString.verify(decoded)
        algorithmBytes.verify(decoded)
    }

    @Test
    fun shouldFailHMAC256VerificationWithInvalidSecretString() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"
        val algorithm = Algorithm.HMAC256("not_real_secret") as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256", t.message)
    }

    @Test
    fun shouldFailHMAC256VerificationWithInvalidSecretBytes() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"
        val algorithm = Algorithm.HMAC256("not_real_secret".toByteArray()) as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256", t.message)
    }

    @Test
    fun shouldPassHMAC384Verification() {
        val jwt =
            "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw"

        val algorithmString = Algorithm.HMAC384("secret") as HMACAlgorithm
        val algorithmBytes = Algorithm.HMAC384("secret".toByteArray()) as HMACAlgorithm

        val decoded: DecodedJWT = JWT.decode(jwt)

        algorithmString.verify(decoded)
        algorithmBytes.verify(decoded)
    }

    @Test
    fun shouldFailHMAC384VerificationWithInvalidSecretString() {
        val jwt =
            "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw"
        val algorithm = Algorithm.HMAC384("not_real_secret") as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384", t.message)
    }

    @Test
    fun shouldFailHMAC384VerificationWithInvalidSecretBytes() {
        val jwt =
            "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw"
        val algorithm = Algorithm.HMAC384("not_real_secret".toByteArray()) as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384", t.message)
    }

    @Test
    fun shouldPassHMAC512Verification() {
        val jwt =
            "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw"

        val algorithmString = Algorithm.HMAC512("secret") as HMACAlgorithm
        val algorithmBytes = Algorithm.HMAC512("secret".toByteArray()) as HMACAlgorithm

        val decoded: DecodedJWT = JWT.decode(jwt)

        algorithmString.verify(decoded)
        algorithmBytes.verify(decoded)
    }

    @Test
    fun shouldFailHMAC512VerificationWithInvalidSecretString() {
        val jwt =
            "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw"
        val algorithm = Algorithm.HMAC512("not_real_secret") as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512", t.message)
    }

    @Test
    fun shouldFailHMAC512VerificationWithInvalidSecretBytes() {
        val jwt =
            "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw"
        val algorithm = Algorithm.HMAC512("not_real_secret".toByteArray()) as HMACAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512", t.message)
    }

    @Test
    fun shouldThrowOnVerifyWhenSignatureAlgorithmDoesNotExists() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        val algorithm = HMACAlgorithm(
            id = "some-alg",
            algorithm = "some-algorithm",
            secretBytes = "secret".toByteArray(),
        )

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                secretBytes = any<ByteArray>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)
        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowOnVerifyWhenTheSecretIsInvalid() {
        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        val algorithm = HMACAlgorithm(
            id = "some-alg",
            algorithm = "some-algorithm",
            secretBytes = "secret".toByteArray(),
        )

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                secretBytes = any<ByteArray>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws InvalidKeyException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)
        assertIs<InvalidKeyException>(t.cause)
    }

    @Test
    fun shouldDoHMAC256SigningWithBytes() {
        val expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho"

        val algorithm = Algorithm.HMAC256("secret".toByteArray()) as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoHMAC384SigningWithBytes() {
        val expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt"
        val algorithm = Algorithm.HMAC384("secret".toByteArray()) as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoHMAC512SigningWithBytes() {
        val expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw"
        val algorithm = Algorithm.HMAC512("secret".toByteArray()) as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoHMAC256SigningWithString() {
        val expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho"
        val algorithm = Algorithm.HMAC256("secret") as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoHMAC384SigningWithString() {
        val algorithm = Algorithm.HMAC384("secret") as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS384Header,
            auth0IssPayload,
        )
        val expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt"

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoHMAC512SigningWithString() {
        val expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw"
        val algorithm = Algorithm.HMAC512("secret") as HMACAlgorithm

        val jwt: String = asJWT(
            algorithm,
            HS512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() {
        val algorithm = HMACAlgorithm(
            id = "some-alg",
            algorithm = "some-algorithm",
            secretBytes = "secret".toByteArray(),
        )

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            createSignatureFor(
                algorithm = any<String>(),
                privateKey = any<PrivateKey>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
            )
        } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)
        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenTheSecretIsInvalid() {
        val algorithm = HMACAlgorithm(
            id = "some-alg",
            algorithm = "some-algorithm",
            secretBytes = "secret".toByteArray(),
        )

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            createSignatureFor(
                algorithm = any<String>(),
                secretBytes = any<ByteArray>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
            )
        } throws InvalidKeyException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)
        assertIs<InvalidKeyException>(t.cause)
    }

    @Test
    fun shouldReturnNullSigningKeyId() {
        assertNull((Algorithm.HMAC256("secret") as HMACAlgorithm).signingKeyId)
    }

    @Test
    fun shouldBeEqualSignatureMethodResults() {
        val algorithm = Algorithm.HMAC256("secret") as HMACAlgorithm

        val header = byteArrayOf(0x00, 0x01, 0x02)
        val payload = byteArrayOf(0x04, 0x05, 0x06)

        val bout = java.io.ByteArrayOutputStream()
        bout.write(header)
        bout.write('.'.code)
        bout.write(payload)

        assertTrue { algorithm.sign(bout.toByteArray()).contentEquals(algorithm.sign(header, payload)) }
    }

    @Test
    fun shouldThrowWhenSignatureNotValidBase64() {
        val algorithm = HMACAlgorithm(
            id = "some-alg",
            algorithm = "some-algorithm",
            secretBytes = "secret".toByteArray(),
        )

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                secretBytes = any<ByteArray>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws NoSuchAlgorithmException()

        val jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWm+i903JuUoDRZDBPB7HwkS4nVyWH1M"

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)
        assertIs<IllegalArgumentException>(t.cause)
    }

    @Suppress("ktlint:standard:property-naming")
    companion object {
        // Sign
        private const val HS256Header = "eyJhbGciOiJIUzI1NiJ9"
        private const val HS384Header = "eyJhbGciOiJIUzM4NCJ9"
        private const val HS512Header = "eyJhbGciOiJIUzUxMiJ9"
        private const val auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9"
    }
}
