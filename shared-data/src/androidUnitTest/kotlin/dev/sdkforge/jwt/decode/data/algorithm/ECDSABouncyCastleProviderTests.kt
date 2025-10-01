package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.PublicKey
import dev.sdkforge.crypto.domain.ec.asNativeECPrivateKey
import dev.sdkforge.crypto.domain.ec.asNativeECPublicKey
import dev.sdkforge.jwt.decode.data.JWT
import dev.sdkforge.jwt.decode.data.algorithm.ECDSAAlgorithmTest.Companion.assertValidDERSignature
import dev.sdkforge.jwt.decode.data.algorithm.ECDSAAlgorithmTest.Companion.assertValidJOSESignature
import dev.sdkforge.jwt.decode.data.algorithm.ECDSAAlgorithmTest.Companion.createDERSignature
import dev.sdkforge.jwt.decode.data.algorithm.ECDSAAlgorithmTest.Companion.createJOSESignature
import dev.sdkforge.jwt.decode.data.readPrivateKey
import dev.sdkforge.jwt.decode.data.readPublicKey
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureException
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import dev.sdkforge.jwt.decode.domain.provider.ECDSAKeyProvider
import io.mockk.every
import io.mockk.junit4.MockKRule
import io.mockk.mockk
import io.mockk.mockkStatic
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.Rule

class ECDSABouncyCastleProviderTests {

    @get:Rule
    val mockkRule = MockKRule(this)

    @Test
    fun shouldPreferBouncyCastleProvider() {
        assertEquals(bcProvider, java.security.Security.getProviders()[0])
    }

    @Test
    fun shouldPassECDSA256VerificationWithJOSESignature() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"
        val key = readPublicKey<ECPublicKey>(
            PUBLIC_KEY_FILE_256,
            "EC",
        ).asNativeECPublicKey
        val algorithm = Algorithm.ECDSA256(key) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnECDSA256VerificationWithDERSignature() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.MEYCIQDiJWTf5jShFPj0hpCWn7x1nhxPMjKWCs9MMusS9AIhAMcFPJVLe2A9uvb8hl8sRO2IpGoKDRpDmyH14ixNPAHW"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey
        val algorithm = Algorithm.ECDSA256(key) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA256VerificationWithJOSESignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"
        val algorithm = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnECDSA256VerificationWithDERSignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.MEYCIQDiJWTf5jShFPj0hpCWn7x1nhxPMjKWCs9MMusS9AIhAMcFPJVLe2A9uvb8hl8sRO2IpGoKDRpDmyH14ixNPAHW"
        val algorithm = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA256VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.D_oU4CB0ZEsxHOjcWnmS3ZJvlTzm6WcGFx-HASxnvcB2Xu2WjI-axqXH9xKq45aPBDs330JpRhJmqBSc2K8MXQ"
        val publicKey = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns publicKey
        }
        val algorithm = Algorithm.ECDSA256(provider) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailECDSA256VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.D_oU4CB0ZEsxHOjcWnmS3ZJvlTzm6WcGFx-HASxnvcB2Xu2WjI-axqXH9xKq45aPBDs330JpRhJmqBSc2K8MXQ"
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }
        val algorithm = Algorithm.ECDSA256(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA256VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.W9qfN1b80B9hnMo49WL8THrOsf1vEjOhapeFemPMGySzxTcgfyudS5esgeBTO908X5SLdAr5jMwPUPBs9b6nNg"
        val algorithm = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA256VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.W9qfN1b80B9hnMo49WL8THrOsf1vEjOhapeFemPMGySzxTcgfyudS5esgeBTO908X5SLdAr5jMwPUPBs9b6nNg"
        val algorithm = Algorithm.ECDSA256(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA256VerificationOnInvalidJOSESignatureLength() {
        val bytes = ByteArray(63)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA256(
            (readPublicKey(INVALID_PUBLIC_KEY_FILE_256, "EC") as ECPublicKey).asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldFailECDSA256VerificationOnInvalidJOSESignature() {
        val bytes = ByteArray(64)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA256(
            (readPublicKey(INVALID_PUBLIC_KEY_FILE_256, "EC") as ECPublicKey).asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA256VerificationOnInvalidDERSignature() {
        val bytes = ByteArray(64)
        bytes[0] = 0x30
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA256(
            (readPublicKey(INVALID_PUBLIC_KEY_FILE_256, "EC") as ECPublicKey).asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
    }

    @Test
    fun shouldPassECDSA384VerificationWithJOSESignature() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC")
        val algorithm = Algorithm.ECDSA384(key.asNativeECPublicKey) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnECDSA384VerificationWithDERSignature() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.MGUCMQDnRRTlUo10XXBKRjyNAEqm4dmh7ohkEmbk2gHxtH6GdGDq2L4IduahG2UtccCMH8CE2vHCTMuk3pzAtoOtxkB8rXPK2KF6m8LUuEdCqPwF2yxVJn8ZxpzAurDEv8w"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey
        val algorithm = Algorithm.ECDSA384(key) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA384VerificationWithJOSESignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnECDSA384VerificationWithDERSignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.MGUCMQDnRRTlUo10XXBKRjyNAEqm4dmh7ohkEmbk2gHxtH6GdGDq2L4IduahG2UtccCMH8CE2vHCTMuk3pzAtoOtxkB8rXPK2KF6m8LUuEdCqPwF2yxVJn8ZxpzAurDEv8w"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA384VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.9kjGuFTPx3ylfpqL0eY9H7TGmPepjQOBKI8UPoEvby6N7dDLF5HxLohosNxxFymNT7LzpeSgOPAB0wJEwG2Nl2ukgdUOpZOf492wog_i5ZcZmAykd3g1QH7onrzd69GU"
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey
        }
        val algorithm = Algorithm.ECDSA384(provider) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailECDSA384VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJFUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.9kjGuFTPx3ylfpqL0eY9H7TGmPepjQOBKI8UPoEvby6N7dDLF5HxLohosNxxFymNT7LzpeSgOPAB0wJEwG2Nl2ukgdUOpZOf492wog_i5ZcZmAykd3g1QH7onrzd69GU"
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }
        val algorithm = Algorithm.ECDSA384(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA384VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9._k5h1KyO-NE0R2_HAw0-XEc0bGT5atv29SxHhOGC9JDqUHeUdptfCK_ljQ01nLVt2OQWT2SwGs-TuyHDFmhPmPGFZ9wboxvq_ieopmYqhQilNAu-WF-frioiRz9733fU"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA384VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9._k5h1KyO-NE0R2_HAw0-XEc0bGT5atv29SxHhOGC9JDqUHeUdptfCK_ljQ01nLVt2OQWT2SwGs-TuyHDFmhPmPGFZ9wboxvq_ieopmYqhQilNAu-WF-frioiRz9733fU"
        val algorithm = Algorithm.ECDSA384(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA384VerificationOnInvalidJOSESignatureLength() {
        val bytes = ByteArray(95)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldFailECDSA384VerificationOnInvalidJOSESignature() {
        val bytes = ByteArray(96)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA384VerificationOnInvalidDERSignature() {
        val bytes = ByteArray(96)
        java.security.SecureRandom().nextBytes(bytes)
        bytes[0] = 0x30
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA", t.message)
    }

    @Test
    fun shouldPassECDSA512VerificationWithJOSESignature() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey
        val algorithm = Algorithm.ECDSA512(key) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowOnECDSA512VerificationWithDERSignature() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.MIGIAkIB4Ik8MixIeHBFIZkJjquymLzN6Q7DQr2pgw2uJ0UW726GsDVCsb4RTFeUTTrKaHZHtHPRoTuTEHCuerwvxo4EICQgGALKocz3lL8qfH1444LNBLaOSNJp3RNkB5YHDEhQEsox21PMA9kau2TcxkOW9jGX6b9N9FhlGo0mmWFhVCR1YNg"
        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC")
        val algorithm = Algorithm.ECDSA512(key.asNativeECPublicKey) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA512VerificationWithJOSESignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldThrowECDSA512VerificationWithDERSignatureWithBothKeys() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.MIGIAkIB4Ik8MixIeHBFIZkJjquymLzN6Q7DQr2pgw2uJ0UW726GsDVCsb4RTFeUTTrKaHZHtHPRoTuTEHCuerwvxo4EICQgGALKocz3lL8qfH1444LNBLaOSNJp3RNkB5YHDEhQEsox21PMA9kau2TcxkOW9jGX6b9N9FhlGo0mmWFhVCR1YNg"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldPassECDSA512VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.AGxEwbsYa2bQ7Y7DAcTQnVD8PmLSlhJ20jg2OfdyPnqdXI8SgBaG6lGciq3_pofFhs1HEoFoJ33Jcluha24oMHIvAfwu8qbv_Wq3L2eI9Q0L0p6ul8Pd_BS8adRa2PgLc36xXGcRc7ID5YH-CYaQfsTp5YIaF0Po3h0QyCoQ6ZiYQkqm"
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey
        }

        val algorithm = Algorithm.ECDSA512(provider) as ECDSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailECDSA512VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJFUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.AGxEwbsYa2bQ7Y7DAcTQnVD8PmLSlhJ20jg2OfdyPnqdXI8SgBaG6lGciq3_pofFhs1HEoFoJ33Jcluha24oMHIvAfwu8qbv_Wq3L2eI9Q0L0p6ul8Pd_BS8adRa2PgLc36xXGcRc7ID5YH-CYaQfsTp5YIaF0Po3h0QyCoQ6ZiYQkqm"
        val provider: ECDSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }
        val algorithm = Algorithm.ECDSA512(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA512VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AZgdopFFsN0amCSs2kOucXdpylD31DEm5ChK1PG0_gq5Mf47MrvVph8zHSVuvcrXzcE1U3VxeCg89mYW1H33Y-8iAF0QFkdfTUQIWKNObH543WNMYYssv3OtOj0znPv8atDbaF8DMYAtcT1qdmaSJRhx-egRE9HGZkinPh9CfLLLt58X"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA512VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AZgdopFFsN0amCSs2kOucXdpylD31DEm5ChK1PG0_gq5Mf47MrvVph8zHSVuvcrXzcE1U3VxeCg89mYW1H33Y-8iAF0QFkdfTUQIWKNObH543WNMYYssv3OtOj0znPv8atDbaF8DMYAtcT1qdmaSJRhx-egRE9HGZkinPh9CfLLLt58X"
        val algorithm = Algorithm.ECDSA512(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailECDSA512VerificationOnInvalidJOSESignatureLength() {
        val bytes = ByteArray(131)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldFailECDSA512VerificationOnInvalidJOSESignature() {
        val bytes = ByteArray(132)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
    }

    @Test
    fun shouldFailECDSA512VerificationOnInvalidDERSignature() {
        val bytes = ByteArray(132)
        java.security.SecureRandom().nextBytes(bytes)
        bytes[0] = 0x30
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(INVALID_PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA", t.message)
    }

    @Test
    fun shouldFailJOSEToDERConversionOnInvalidJOSESignatureLength() {
        val bytes = ByteArray(256)
        java.security.SecureRandom().nextBytes(bytes)
        val signature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(bytes)
        val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.$signature"

        val publicKey = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC")
        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("ES256", "SHA256withECDSA", 128, provider)

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("Invalid JOSE signature format.", t.cause?.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldThrowOnVerifyWhenSignatureAlgorithmDoesNotExists() {
        val a = ByteArray(64)
        java.util.Arrays.fill(a, Byte.MAX_VALUE)
        val publicKey: ECPublicKey = mockk {
            every { params } returns mockk<ECParameterSpec>()
            every { params.order } returns BigInteger(a)
        }

        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)

        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowOnVerifyWhenThePublicKeyIsInvalid() {
        val a = ByteArray(64)
        java.util.Arrays.fill(a, Byte.MAX_VALUE)
        val publicKey: ECPublicKey = mockk {
            every { params } returns mockk<ECParameterSpec>()
            every { params.order } returns BigInteger(a)
        }

        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                publicKey = any<PublicKey>(),
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
    fun shouldThrowOnVerifyWhenTheSignatureIsNotPrepared() {
        val a = ByteArray(64)
        java.util.Arrays.fill(a, Byte.MAX_VALUE)
        val publicKey: ECPublicKey = mockk {
            every { params } returns mockk<ECParameterSpec>()
            every { params.order } returns BigInteger(a)
        }

        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)
        val jwt =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                publicKey = any<PublicKey>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws SignatureException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldDoECDSA256Signing() {
        val algorithmSign = Algorithm.ECDSA256(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm
        val algorithmVerify = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm
        val jwt: String = asJWT(
            algorithmSign,
            ES256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA256SigningWithBothKeys() {
        val algorithm = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm
        val jwt: String = asJWT(
            algorithm,
            ES256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA256SigningWithProvidedPrivateKey() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC").asNativeECPrivateKey
            every { getPublicKeyById(null) } returns readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey
        }

        val algorithm = Algorithm.ECDSA256(provider) as ECDSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            ES256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnECDSA256SigningWhenProvidedPrivateKeyIsNull() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns null
        }
        val algorithm = Algorithm.ECDSA256(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnECDSA256SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldDoECDSA384Signing() {
        val algorithmSign = Algorithm.ECDSA384(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm
        val algorithmVerify = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm
        val jwt: String = asJWT(
            algorithmSign,
            ES384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA384SigningWithBothKeys() {
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            ES384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA384SigningWithProvidedPrivateKey() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC").asNativeECPrivateKey
            every { getPublicKeyById(null) } returns readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey
        }
        val algorithm = Algorithm.ECDSA384(provider) as ECDSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            ES384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnECDSA384SigningWhenProvidedPrivateKeyIsNull() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns null
        }
        val algorithm = Algorithm.ECDSA384(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnECDSA384SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldDoECDSA512Signing() {
        val algorithmSign = Algorithm.ECDSA512(
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC").asNativeECPrivateKey,
        ) as ECDSAAlgorithm
        val algorithmVerify = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val jwt: String = asJWT(
            algorithmSign,
            ES512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA512SigningWithBothKeys() {
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            ES512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoECDSA512SigningWithProvidedPrivateKey() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC").asNativeECPrivateKey
            every { getPublicKeyById(null) } returns readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey
        }
        val algorithm = Algorithm.ECDSA512(provider) as ECDSAAlgorithm
        val jwt: String = asJWT(
            algorithm,
            ES512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnECDSA512SigningWhenProvidedPrivateKeyIsNull() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKey } returns null
        }
        val algorithm = Algorithm.ECDSA512(provider) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnECDSA512SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC").asNativeECPublicKey,
        ) as ECDSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withECDSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() {
        val publicKey: ECPublicKey = mockk()
        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(
                ES256Header.toByteArray(java.nio.charset.StandardCharsets.UTF_8),
                ByteArray(0),
            )
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenThePrivateKeyIsInvalid() {
        val publicKey: ECPublicKey = mockk()
        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws InvalidKeyException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(
                ES256Header.toByteArray(java.nio.charset.StandardCharsets.UTF_8),
                ByteArray(0),
            )
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<InvalidKeyException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenTheSignatureIsNotPrepared() {
        val publicKey: ECPublicKey = mockk()
        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws SignatureException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(
                ES256Header.toByteArray(java.nio.charset.StandardCharsets.UTF_8),
                ByteArray(0),
            )
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldReturnNullSigningKeyIdIfCreatedWithDefaultProvider() {
        val publicKey: ECPublicKey = mockk()
        val privateKey: ECPrivateKey = mockk()
        val provider: ECDSAKeyProvider = ECDSAAlgorithm.providerForKeys(publicKey.asNativeECPublicKey, privateKey.asNativeECPrivateKey)
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)

        assertNull(algorithm.signingKeyId)
    }

    @Test
    fun shouldReturnSigningKeyIdFromProvider() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKeyId } returns "keyId"
        }
        val algorithm = ECDSAAlgorithm("some-alg", "some-algorithm", 32, provider)

        assertEquals("keyId", algorithm.signingKeyId)
    }

    @Test
    fun shouldThrowOnDERSignatureConversionIfDoesNotStartWithCorrectSequenceByte() {
        val content256 = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9"
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm
        val signature = algorithm256.sign(content256.toByteArray(), ByteArray(0))

        signature[0] = 0x02.toByte()

        val t = assertFailsWith<SignatureException> {
            algorithm256.DERToJOSE(signature)
        }

        assertEquals("Invalid DER signature format.", t.message)
    }

    @Test
    fun shouldThrowOnDERSignatureConversionIfDoesNotHaveExpectedLength() {
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm
        val derSignature = createDERSignature(32, false, false)
        var received = derSignature[1].toInt()
        received--
        derSignature[1] = received.toByte()

        val t = assertFailsWith<SignatureException> {
            algorithm256.DERToJOSE(derSignature)
        }

        assertEquals("Invalid DER signature format.", t.message)
    }

    @Test
    fun shouldThrowOnDERSignatureConversionIfRNumberDoesNotHaveExpectedLength() {
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm
        val derSignature = createDERSignature(32, false, false)

        derSignature[3] = 34.toByte()

        val t = assertFailsWith<SignatureException> {
            algorithm256.DERToJOSE(derSignature)
        }

        assertEquals("Invalid DER signature format.", t.message)
    }

    @Test
    fun shouldThrowOnDERSignatureConversionIfSNumberDoesNotHaveExpectedLength() {
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm
        val derSignature = createDERSignature(32, false, false)

        derSignature[4 + 32 + 1] = 34.toByte()

        val t = assertFailsWith<SignatureException> {
            algorithm256.DERToJOSE(derSignature)
        }

        assertEquals("Invalid DER signature format.", t.message)
    }

    @Test
    fun shouldThrowOnJOSESignatureConversionIfDoesNotHaveExpectedLength() {
        val publicKey = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC")
        val privateKey = readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC")
        val algorithm256 = Algorithm.ECDSA256(publicKey, privateKey) as ECDSAAlgorithm
        val joseSignature = ByteArray(32 * 2 - 1)

        val t = assertFailsWith<SignatureException> {
            algorithm256.validateSignatureStructure(joseSignature, publicKey.asNativeECPublicKey)
        }

        assertEquals("Invalid JOSE signature format.", t.message)
    }

    @Test
    fun shouldSignAndVerifyWithECDSA256() {
        val header256 = "eyJhbGciOiJFUzI1NiJ9"
        val body = "eyJpc3MiOiJhdXRoMCJ9"
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm

        for (i in 0..9) {
            val jwt: String = asJWT(algorithm256, header256, body)
            algorithm256.verify(JWT.decode(jwt))
        }
    }

    @Test
    fun shouldSignAndVerifyWithECDSA384() {
        val header384 = "eyJhbGciOiJFUzM4NCJ9"
        val body = "eyJpc3MiOiJhdXRoMCJ9"
        val algorithm384 = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        for (i in 0..9) {
            val jwt: String = asJWT(algorithm384, header384, body)
            algorithm384.verify(JWT.decode(jwt))
        }
    }

    @Test
    fun shouldSignAndVerifyWithECDSA512() {
        val header512 = "eyJhbGciOiJFUzUxMiJ9"
        val body = "eyJpc3MiOiJhdXRoMCJ9"
        val algorithm512 = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        for (i in 0..9) {
            val jwt: String = asJWT(algorithm512, header512, body)
            algorithm512.verify(JWT.decode(jwt))
        }
    }

    @Test
    fun shouldDecodeECDSA256JOSE() {
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var joseSignature = createJOSESignature(32, withRPadding = false, withSPadding = false)
        var derSignature = algorithm256.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 32, withRPadding = false, withSPadding = false)

        // With R padding
        joseSignature = createJOSESignature(32, withRPadding = true, withSPadding = false)
        derSignature = algorithm256.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 32, withRPadding = true, withSPadding = false)

        // With S padding
        joseSignature = createJOSESignature(32, withRPadding = false, withSPadding = true)
        derSignature = algorithm256.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 32, withRPadding = false, withSPadding = true)

        // With both paddings
        joseSignature = createJOSESignature(32, withRPadding = true, withSPadding = true)
        derSignature = algorithm256.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 32, withRPadding = true, withSPadding = true)
    }

    @Test
    fun shouldDecodeECDSA256DER() {
        val algorithm256 = Algorithm.ECDSA256(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_256, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var derSignature = createDERSignature(32, withRPadding = false, withSPadding = false)
        var joseSignature = algorithm256.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 32, withRPadding = false, withSPadding = false)

        // With R padding
        derSignature = createDERSignature(32, withRPadding = true, withSPadding = false)
        joseSignature = algorithm256.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 32, withRPadding = true, withSPadding = false)

        // With S padding
        derSignature = createDERSignature(32, withRPadding = false, withSPadding = true)
        joseSignature = algorithm256.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 32, withRPadding = false, withSPadding = true)

        // With both paddings
        derSignature = createDERSignature(32, withRPadding = true, withSPadding = true)
        joseSignature = algorithm256.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 32, withRPadding = true, withSPadding = true)
    }

    @Test
    fun shouldDecodeECDSA384JOSE() {
        val algorithm384 = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var joseSignature = createJOSESignature(48, withRPadding = false, withSPadding = false)
        var derSignature = algorithm384.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 48, withRPadding = false, withSPadding = false)

        // With R padding
        joseSignature = createJOSESignature(48, withRPadding = true, withSPadding = false)
        derSignature = algorithm384.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 48, withRPadding = true, withSPadding = false)

        // With S padding
        joseSignature = createJOSESignature(48, withRPadding = false, withSPadding = true)
        derSignature = algorithm384.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 48, withRPadding = false, withSPadding = true)

        // With both paddings
        joseSignature = createJOSESignature(48, withRPadding = true, withSPadding = true)
        derSignature = algorithm384.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 48, withRPadding = true, withSPadding = true)
    }

    @Test
    fun shouldDecodeECDSA384DER() {
        val algorithm384 = Algorithm.ECDSA384(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_384, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var derSignature = createDERSignature(48, withRPadding = false, withSPadding = false)
        var joseSignature = algorithm384.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 48, withRPadding = false, withSPadding = false)

        // With R padding
        derSignature = createDERSignature(48, withRPadding = true, withSPadding = false)
        joseSignature = algorithm384.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 48, withRPadding = true, withSPadding = false)

        // With S padding
        derSignature = createDERSignature(48, withRPadding = false, withSPadding = true)
        joseSignature = algorithm384.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 48, withRPadding = false, withSPadding = true)

        // With both paddings
        derSignature = createDERSignature(48, withRPadding = true, withSPadding = true)
        joseSignature = algorithm384.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 48, withRPadding = true, withSPadding = true)
    }

    @Test
    fun shouldDecodeECDSA512JOSE() {
        val algorithm512 = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var joseSignature = createJOSESignature(66, withRPadding = false, withSPadding = false)
        var derSignature = algorithm512.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 66, withRPadding = false, withSPadding = false)

        // With R padding
        joseSignature = createJOSESignature(66, withRPadding = true, withSPadding = false)
        derSignature = algorithm512.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 66, withRPadding = true, withSPadding = false)

        // With S padding
        joseSignature = createJOSESignature(66, withRPadding = false, withSPadding = true)
        derSignature = algorithm512.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 66, withRPadding = false, withSPadding = true)

        // With both paddings
        createJOSESignature(66, withRPadding = true, withSPadding = true).also { joseSignature = it }
        derSignature = algorithm512.JOSEToDER(joseSignature)

        assertValidDERSignature(derSignature, 66, withRPadding = true, withSPadding = true)
    }

    @Test
    fun shouldDecodeECDSA512DER() {
        val algorithm512 = Algorithm.ECDSA512(
            readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC"),
            readPrivateKey<ECPrivateKey>(PRIVATE_KEY_FILE_512, "EC"),
        ) as ECDSAAlgorithm

        // Without padding
        var derSignature = createDERSignature(66, withRPadding = false, withSPadding = false)
        var joseSignature = algorithm512.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 66, withRPadding = false, withSPadding = false)

        // With R padding
        derSignature = createDERSignature(66, withRPadding = true, withSPadding = false)
        joseSignature = algorithm512.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 66, withRPadding = true, withSPadding = false)

        // With S padding
        derSignature = createDERSignature(66, withRPadding = false, withSPadding = true)
        joseSignature = algorithm512.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 66, withRPadding = false, withSPadding = true)

        // With both paddings
        derSignature = createDERSignature(66, withRPadding = true, withSPadding = true)
        joseSignature = algorithm512.DERToJOSE(derSignature)

        assertValidJOSESignature(joseSignature, 66, withRPadding = true, withSPadding = true)
    }

    // JOSE Signatures obtained using Node 'jwa' lib: https://github.com/brianloveswords/node-jwa
    // DER Signatures obtained from source JOSE signature using 'ecdsa-sig-formatter' lib: https://github.com/Brightspace/node-ecdsa-sig-formatter
    // These tests add and use the BouncyCastle SecurityProvider to handle ECDSA algorithms
    @Before
    fun setUp() {
        // Set BC as the preferred bcProvider
        java.security.Security.insertProviderAt(bcProvider, 1)
    }

    @After
    fun tearDown() {
        java.security.Security.removeProvider(bcProvider.name)
    }

    @Suppress("ktlint:standard:property-naming")
    companion object {
        private const val PRIVATE_KEY_FILE_256 = "src/androidUnitTest/resources/ec256-key-private.pem"
        private const val PUBLIC_KEY_FILE_256 = "src/androidUnitTest/resources/ec256-key-public.pem"
        private const val INVALID_PUBLIC_KEY_FILE_256 = "src/androidUnitTest/resources/ec256-key-public-invalid.pem"

        private const val PRIVATE_KEY_FILE_384 = "src/androidUnitTest/resources/ec384-key-private.pem"
        private const val PUBLIC_KEY_FILE_384 = "src/androidUnitTest/resources/ec384-key-public.pem"
        private const val INVALID_PUBLIC_KEY_FILE_384 = "src/androidUnitTest/resources/ec384-key-public-invalid.pem"

        private const val PRIVATE_KEY_FILE_512 = "src/androidUnitTest/resources/ec512-key-private.pem"
        private const val PUBLIC_KEY_FILE_512 = "src/androidUnitTest/resources/ec512-key-public.pem"
        private const val INVALID_PUBLIC_KEY_FILE_512 = "src/androidUnitTest/resources/ec512-key-public-invalid.pem"

        private val bcProvider: java.security.Provider = BouncyCastleProvider()

        // Sign
        private const val ES256Header = "eyJhbGciOiJFUzI1NiJ9"
        private const val ES384Header = "eyJhbGciOiJFUzM4NCJ9"
        private const val ES512Header = "eyJhbGciOiJFUzUxMiJ9"
        private const val auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9"
    }
}
