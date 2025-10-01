@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import kotlin.io.encoding.Base64

/**
 * Subclass representing an Hash-based MAC signing algorithm.
 */
internal class HMACAlgorithm(
    id: String,
    algorithm: String,
    secretBytes: ByteArray,
) : Algorithm(
    name = id,
    description = algorithm,
),
    VerificationAlgorithm,
    SigningAlgorithm {

    private val secret: ByteArray = secretBytes.copyOf()

    constructor(id: String, algorithm: String, secret: String) : this(id, algorithm, getSecretBytes(secret))

    @Throws(SignatureVerificationException::class)
    override fun verify(jwt: DecodedJWT) {
        try {
            val signatureBytes: ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(jwt.signature)
            val valid: Boolean = verifySignature(
                algorithm = description,
                secretBytes = secret,
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

    @Throws(SignatureGenerationException::class)
    override fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): ByteArray {
        try {
            return createSignatureFor(description, secret, headerBytes, payloadBytes)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    @Throws(SignatureGenerationException::class)
    override fun sign(contentBytes: ByteArray): ByteArray {
        try {
            return createSignatureFor(description, secret, contentBytes)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    companion object {
        // Visible for testing
        @Throws(IllegalArgumentException::class)
        internal fun getSecretBytes(secret: String): ByteArray = secret.encodeToByteArray()
    }
}
