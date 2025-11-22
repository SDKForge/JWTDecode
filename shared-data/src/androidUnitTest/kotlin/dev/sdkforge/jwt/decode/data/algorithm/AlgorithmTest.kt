package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.ec.ECKey
import dev.sdkforge.crypto.domain.ec.ECPrivateKey
import dev.sdkforge.crypto.domain.ec.ECPublicKey
import dev.sdkforge.crypto.domain.rsa.RSAKey
import dev.sdkforge.crypto.domain.rsa.RSAPrivateKey
import dev.sdkforge.crypto.domain.rsa.RSAPublicKey
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.provider.ECDSAKeyProvider
import dev.sdkforge.jwt.decode.domain.provider.RSAKeyProvider
import io.mockk.junit4.MockKRule
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import org.junit.Rule
import org.junit.Test

class AlgorithmTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    @Test
    fun shouldThrowRSA256InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.RSA256(key = mockk<RSAKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldThrowRSA384InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.RSA384(key = mockk<RSAKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldThrowRSA512InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.RSA512(key = mockk<RSAKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldThrowECDSA256InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.ECDSA256(key = mockk<ECKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldThrowECDSA384InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.ECDSA384(key = mockk<ECKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldThrowECDSA512InstanceWithNullKey() {
        val t = assertFailsWith<IllegalArgumentException> {
            Algorithm.ECDSA512(key = mockk<ECKey>())
        }

        assertEquals("Both provided Keys cannot be null.", t.message)
    }

    @Test
    fun shouldCreateHMAC256AlgorithmWithBytes() {
        val algorithm = Algorithm.HMAC256("secret".toByteArray())

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA256", algorithm.description)
        assertEquals("HS256", algorithm.name)
    }

    @Test
    fun shouldCreateHMAC384AlgorithmWithBytes() {
        val algorithm = Algorithm.HMAC384("secret".toByteArray())

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA384", algorithm.description)
        assertEquals("HS384", algorithm.name)
    }

    @Test
    fun shouldCreateHMAC512AlgorithmWithBytes() {
        val algorithm = Algorithm.HMAC512("secret".toByteArray())

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA512", algorithm.description)
        assertEquals("HS512", algorithm.name)
    }

    @Test
    fun shouldCreateHMAC256AlgorithmWithString() {
        val algorithm = Algorithm.HMAC256("secret")

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA256", algorithm.description)
        assertEquals("HS256", algorithm.name)
    }

    @Test
    fun shouldCreateHMAC384AlgorithmWithString() {
        val algorithm = Algorithm.HMAC384("secret")

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA384", algorithm.description)
        assertEquals("HS384", algorithm.name)
    }

    @Test
    fun shouldCreateHMAC512AlgorithmWithString() {
        val algorithm = Algorithm.HMAC512("secret")

        assertIs<HMACAlgorithm>(algorithm)
        assertEquals("HmacSHA512", algorithm.description)
        assertEquals("HS512", algorithm.name)
    }

    @Test
    fun shouldCreateRSA256AlgorithmWithPublicKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPublicKey::class))
        val algorithm = Algorithm.RSA256(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA256withRSA", algorithm.description)
        assertEquals("RS256", algorithm.name)
    }

    @Test
    fun shouldCreateRSA256AlgorithmWithPrivateKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPrivateKey::class))
        val algorithm = Algorithm.RSA256(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA256withRSA", algorithm.description)
        assertEquals("RS256", algorithm.name)
    }

    @Test
    fun shouldCreateRSA256AlgorithmWithBothKeys() {
        val publicKey = mockk<RSAPublicKey>()
        val privateKey = mockk<RSAPrivateKey>()
        val algorithm = Algorithm.RSA256(publicKey, privateKey)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA256withRSA", algorithm.description)
        assertEquals("RS256", algorithm.name)
    }

    @Test
    fun shouldCreateRSA256AlgorithmWithProvider() {
        val provider = mockk<RSAKeyProvider>()
        val algorithm = Algorithm.RSA256(provider)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA256withRSA", algorithm.description)
        assertEquals("RS256", algorithm.name)
    }

    @Test
    fun shouldCreateRSA384AlgorithmWithPublicKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPublicKey::class))
        val algorithm = Algorithm.RSA384(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA384withRSA", algorithm.description)
        assertEquals("RS384", algorithm.name)
    }

    @Test
    fun shouldCreateRSA384AlgorithmWithPrivateKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPrivateKey::class))
        val algorithm = Algorithm.RSA384(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA384withRSA", algorithm.description)
        assertEquals("RS384", algorithm.name)
    }

    @Test
    fun shouldCreateRSA384AlgorithmWithBothKeys() {
        val publicKey = mockk<RSAPublicKey>()
        val privateKey = mockk<RSAPrivateKey>()
        val algorithm = Algorithm.RSA384(publicKey, privateKey)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA384withRSA", algorithm.description)
        assertEquals("RS384", algorithm.name)
    }

    @Test
    fun shouldCreateRSA384AlgorithmWithProvider() {
        val provider = mockk<RSAKeyProvider>()
        val algorithm = Algorithm.RSA384(provider)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA384withRSA", algorithm.description)
        assertEquals("RS384", algorithm.name)
    }

    @Test
    fun shouldCreateRSA512AlgorithmWithPublicKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPublicKey::class))
        val algorithm = Algorithm.RSA512(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA512withRSA", algorithm.description)
        assertEquals("RS512", algorithm.name)
    }

    @Test
    fun shouldCreateRSA512AlgorithmWithPrivateKey() {
        val key = mockk<RSAKey>(moreInterfaces = arrayOf(RSAPrivateKey::class))
        val algorithm = Algorithm.RSA512(key)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA512withRSA", algorithm.description)
        assertEquals("RS512", algorithm.name)
    }

    @Test
    fun shouldCreateRSA512AlgorithmWithBothKeys() {
        val publicKey = mockk<RSAPublicKey>()
        val privateKey = mockk<RSAPrivateKey>()
        val algorithm = Algorithm.RSA512(publicKey, privateKey)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA512withRSA", algorithm.description)
        assertEquals("RS512", algorithm.name)
    }

    @Test
    fun shouldCreateRSA512AlgorithmWithProvider() {
        val provider = mockk<RSAKeyProvider>()
        val algorithm = Algorithm.RSA512(provider)

        assertIs<RSAAlgorithm>(algorithm)
        assertEquals("SHA512withRSA", algorithm.description)
        assertEquals("RS512", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA256AlgorithmWithPublicKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPublicKey::class))
        val algorithm = Algorithm.ECDSA256(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA256withECDSA", algorithm.description)
        assertEquals("ES256", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA256AlgorithmWithPrivateKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPrivateKey::class))
        val algorithm = Algorithm.ECDSA256(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA256withECDSA", algorithm.description)
        assertEquals("ES256", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA256AlgorithmWithBothKeys() {
        val publicKey = mockk<ECPublicKey>()
        val privateKey = mockk<ECPrivateKey>()
        val algorithm = Algorithm.ECDSA256(publicKey, privateKey)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA256withECDSA", algorithm.description)
        assertEquals("ES256", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA256AlgorithmWithProvider() {
        val provider = mockk<ECDSAKeyProvider>()
        val algorithm = Algorithm.ECDSA256(provider)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA256withECDSA", algorithm.description)
        assertEquals("ES256", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA384AlgorithmWithPublicKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPublicKey::class))
        val algorithm = Algorithm.ECDSA384(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA384withECDSA", algorithm.description)
        assertEquals("ES384", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA384AlgorithmWithPrivateKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPrivateKey::class))
        val algorithm = Algorithm.ECDSA384(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA384withECDSA", algorithm.description)
        assertEquals("ES384", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA384AlgorithmWithBothKeys() {
        val publicKey = mockk<ECPublicKey>()
        val privateKey = mockk<ECPrivateKey>()
        val algorithm = Algorithm.ECDSA384(publicKey, privateKey)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA384withECDSA", algorithm.description)
        assertEquals("ES384", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA384AlgorithmWithProvider() {
        val provider = mockk<ECDSAKeyProvider>()
        val algorithm = Algorithm.ECDSA384(provider)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA384withECDSA", algorithm.description)
        assertEquals("ES384", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA512AlgorithmWithPublicKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPublicKey::class))
        val algorithm = Algorithm.ECDSA512(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA512withECDSA", algorithm.description)
        assertEquals("ES512", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA512AlgorithmWithPrivateKey() {
        val key = mockk<ECKey>(moreInterfaces = arrayOf(ECPrivateKey::class))
        val algorithm = Algorithm.ECDSA512(key)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA512withECDSA", algorithm.description)
        assertEquals("ES512", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA512AlgorithmWithBothKeys() {
        val publicKey = mockk<ECPublicKey>()
        val privateKey = mockk<ECPrivateKey>()
        val algorithm = Algorithm.ECDSA512(publicKey, privateKey)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA512withECDSA", algorithm.description)
        assertEquals("ES512", algorithm.name)
    }

    @Test
    fun shouldCreateECDSA512AlgorithmWithProvider() {
        val provider = mockk<ECDSAKeyProvider>()
        val algorithm = Algorithm.ECDSA512(provider)

        assertIs<ECDSAAlgorithm>(algorithm)
        assertEquals("SHA512withECDSA", algorithm.description)
        assertEquals("ES512", algorithm.name)
    }

    @Test
    fun shouldCreateNoneAlgorithm() {
        val algorithm = Algorithm.NONE

        assertIs<NoneAlgorithm>(algorithm)
        assertEquals("none", algorithm.description)
        assertEquals("none", algorithm.name)
    }
}
