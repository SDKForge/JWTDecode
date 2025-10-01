@file:Suppress("FunctionName", "ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

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

/**
 * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid RSA256 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA256(keyProvider: RSAKeyProvider): Algorithm {
    return RSAAlgorithm(id = "RS256", algorithm = "SHA256withRSA", keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid RSA256 Algorithm.
 * @throws IllegalArgumentException if both provided Keys are null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA256(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): Algorithm {
    return RSA256(keyProvider = RSAAlgorithm.Companion.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid RSA256 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA256(key: RSAKey): Algorithm {
    val publicKey: RSAPublicKey? = key as? RSAPublicKey
    val privateKey: RSAPrivateKey? = key as? RSAPrivateKey
    return RSA256(publicKey = publicKey, privateKey = privateKey)
}

/**
 * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid RSA384 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA384(keyProvider: RSAKeyProvider): Algorithm {
    return RSAAlgorithm(id = "RS384", algorithm = "SHA384withRSA", keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid RSA384 Algorithm.
 * @throws IllegalArgumentException if both provided Keys are null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA384(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): Algorithm {
    return RSA384(keyProvider = RSAAlgorithm.Companion.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid RSA384 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA384(key: RSAKey): Algorithm {
    val publicKey: RSAPublicKey? = key as? RSAPublicKey
    val privateKey: RSAPrivateKey? = key as? RSAPrivateKey
    return RSA384(publicKey = publicKey, privateKey = privateKey)
}

/**
 * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid RSA512 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA512(keyProvider: RSAKeyProvider): Algorithm {
    return RSAAlgorithm(id = "RS512", algorithm = "SHA512withRSA", keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid RSA512 Algorithm.
 * @throws IllegalArgumentException if both provided Keys are null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA512(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): Algorithm {
    return RSA512(keyProvider = RSAAlgorithm.Companion.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid RSA512 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA512(key: RSAKey?): Algorithm {
    val publicKey: RSAPublicKey? = key as? RSAPublicKey
    val privateKey: RSAPrivateKey? = key as? RSAPrivateKey
    return RSA512(publicKey = publicKey, privateKey = privateKey)
}

/**
 * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 256 bit long
 * @return a valid HMAC256 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC256(secret: String): Algorithm {
    return HMACAlgorithm(id = "HS256", algorithm = "HmacSHA256", secret = secret)
}

/**
 * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 256 bit long
 * @return a valid HMAC256 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC256(secret: ByteArray): Algorithm {
    return HMACAlgorithm(id = "HS256", algorithm = "HmacSHA256", secretBytes = secret)
}

/**
 * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 384 bit long
 * @return a valid HMAC384 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC384(secret: String): Algorithm {
    return HMACAlgorithm(id = "HS384", algorithm = "HmacSHA384", secret = secret)
}

/**
 * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 384 bit long
 * @return a valid HMAC384 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC384(secret: ByteArray): Algorithm {
    return HMACAlgorithm(id = "HS384", algorithm = "HmacSHA384", secretBytes = secret)
}

/**
 * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 512 bit long
 * @return a valid HMAC512 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC512(secret: String): Algorithm {
    return HMACAlgorithm(id = "HS512", algorithm = "HmacSHA512", secret = secret)
}

/**
 * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
 *
 * @param secret the secret bytes to use in the verify or signing instance.
 * Ensure the length of the secret is at least 512 bit long
 * @return a valid HMAC512 Algorithm.
 * @throws IllegalArgumentException if the provided Secret is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.HMAC512(secret: ByteArray): Algorithm {
    return HMACAlgorithm(id = "HS512", algorithm = "HmacSHA512", secretBytes = secret)
}

/**
 * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid ECDSA256 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA256(keyProvider: ECDSAKeyProvider): Algorithm {
    return ECDSAAlgorithm(id = "ES256", algorithm = "SHA256withECDSA", ecNumberSize = 32, keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA256 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA256(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA256(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid ECDSA256 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA256(key: ECKey): Algorithm {
    val publicKey: ECPublicKey? = key as? ECPublicKey
    val privateKey: ECPrivateKey? = key as? ECPrivateKey
    return ECDSA256(publicKey = publicKey, privateKey = privateKey)
}

/**
 * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid ECDSA384 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA384(keyProvider: ECDSAKeyProvider): Algorithm {
    return ECDSAAlgorithm(id = "ES384", algorithm = "SHA384withECDSA", ecNumberSize = 48, keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA384 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA384(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA384(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid ECDSA384 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA384(key: ECKey?): Algorithm {
    val publicKey: ECPublicKey? = key as? ECPublicKey
    val privateKey: ECPrivateKey? = key as? ECPrivateKey
    return ECDSA384(publicKey = publicKey, privateKey = privateKey)
}

/**
 * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
 *
 * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
 * @return a valid ECDSA512 Algorithm.
 * @throws IllegalArgumentException if the Key Provider is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA512(keyProvider: ECDSAKeyProvider): Algorithm {
    return ECDSAAlgorithm(id = "ES512", algorithm = "SHA512withECDSA", ecNumberSize = 66, keyProvider = keyProvider)
}

/**
 * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA512 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA512(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA512(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey, privateKey))
}

/**
 * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
 *
 * @param key the key to use in the verify or signing instance.
 * @return a valid ECDSA512 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA512(key: ECKey): Algorithm {
    val publicKey: ECPublicKey? = key as? ECPublicKey
    val privateKey: ECPrivateKey? = key as? ECPrivateKey
    return ECDSA512(publicKey = publicKey, privateKey = privateKey)
}

val Algorithm.Companion.NONE: Algorithm get() = NoneAlgorithm
