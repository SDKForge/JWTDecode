@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.rsa.RSAPrivateKey
import dev.sdkforge.crypto.domain.rsa.RSAPublicKey
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import dev.sdkforge.jwt.decode.domain.provider.RSAKeyProvider
import kotlin.io.encoding.Base64

/**
 * Subclass representing an RSA signing algorithm.
 */
internal class RSAAlgorithm(
    id: String,
    algorithm: String,
    private val keyProvider: RSAKeyProvider,
) : Algorithm(
    name = id,
    description = algorithm,
),
    VerificationAlgorithm,
    SigningAlgorithm {

    @Throws(SignatureVerificationException::class)
    override fun verify(jwt: DecodedJWT) {
        try {
            val signatureBytes: ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(jwt.signature)
            val publicKey: RSAPublicKey? = keyProvider.getPublicKeyById(jwt.keyId)

            checkNotNull(publicKey) { "The given Public Key is null." }

            val valid: Boolean = verifySignature(
                algorithm = description,
                publicKey = publicKey,
                header = jwt.header,
                payload = jwt.payload,
                signatureBytes = signatureBytes,
            )
            if (!valid) {
                throw SignatureVerificationException(this)
            }
        } catch (e: Exception) {
            throw SignatureVerificationException(this, e)
        }
    }

    override val signingKeyId: String?
        get() = keyProvider.privateKeyId

    @Throws(SignatureGenerationException::class)
    override fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): ByteArray {
        try {
            val privateKey: PrivateKey? = keyProvider.privateKey

            checkNotNull(privateKey) { "The given Private Key is null." }

            return createSignatureFor(description, privateKey, headerBytes, payloadBytes)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    @Throws(SignatureGenerationException::class)
    override fun sign(contentBytes: ByteArray): ByteArray {
        try {
            val privateKey: PrivateKey? = keyProvider.privateKey

            checkNotNull(privateKey) { "The given Private Key is null." }

            return createSignatureFor(description, privateKey, contentBytes)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    companion object {
        // Visible for testing
        internal fun providerForKeys(publicKey: RSAPublicKey?, privateKey: RSAPrivateKey?): RSAKeyProvider {
            require(!(publicKey == null && privateKey == null)) { "Both provided Keys cannot be null." }

            return object : RSAKeyProvider {
                override fun getPublicKeyById(keyId: String?): RSAPublicKey? = publicKey
                override val privateKey: RSAPrivateKey? get() = privateKey
                override val privateKeyId: String? get() = null
            }
        }
    }
}
