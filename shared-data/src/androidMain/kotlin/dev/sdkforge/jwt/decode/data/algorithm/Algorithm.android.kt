@file:Suppress("FunctionName", "ktlint:standard:function-expression-body", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.ec.asNativeECPrivateKey
import dev.sdkforge.crypto.domain.ec.asNativeECPublicKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPrivateKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPublicKey
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

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
    return RSA256(keyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey))
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
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid RSA384 Algorithm.
 * @throws IllegalArgumentException if both provided Keys are null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA384(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): Algorithm {
    return RSA384(keyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey))
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
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid RSA512 Algorithm.
 * @throws IllegalArgumentException if both provided Keys are null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.RSA512(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): Algorithm {
    return RSA512(keyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey))
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
 * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
 *
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA256 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA256(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA256(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey?.asNativeECPublicKey, privateKey?.asNativeECPrivateKey))
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
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA384 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA384(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA384(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey?.asNativeECPublicKey, privateKey?.asNativeECPrivateKey))
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
 * @param publicKey  the key to use in the verify instance.
 * @param privateKey the key to use in the signing instance.
 * @return a valid ECDSA512 Algorithm.
 * @throws IllegalArgumentException if the provided Key is null.
 */
@Throws(IllegalArgumentException::class)
fun Algorithm.Companion.ECDSA512(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): Algorithm {
    return ECDSA512(keyProvider = ECDSAAlgorithm.providerForKeys(publicKey?.asNativeECPublicKey, privateKey?.asNativeECPrivateKey))
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
