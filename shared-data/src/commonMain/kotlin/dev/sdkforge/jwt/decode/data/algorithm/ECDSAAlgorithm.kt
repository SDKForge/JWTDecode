@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.ec.ECPrivateKey
import dev.sdkforge.crypto.domain.ec.ECPublicKey
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureException
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import dev.sdkforge.jwt.decode.domain.provider.ECDSAKeyProvider
import kotlin.io.encoding.Base64
import kotlin.math.max
import kotlin.math.min

/**
 * Subclass representing an Elliptic Curve signing algorithm
 */
internal class ECDSAAlgorithm(
    id: String,
    algorithm: String,
    private val ecNumberSize: Int,
    private val keyProvider: ECDSAKeyProvider,
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
            val publicKey: ECPublicKey? = keyProvider.getPublicKeyById(jwt.keyId)

            checkNotNull(publicKey) { "The given Public Key is null." }

            validateSignatureStructure(signatureBytes, publicKey)

            val valid: Boolean = verifySignature(
                algorithm = description,
                publicKey = publicKey,
                header = jwt.header,
                payload = jwt.payload,
                signatureBytes = JOSEToDER(
                    joseSignature = signatureBytes,
                ),
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
            val privateKey: ECPrivateKey? = keyProvider.privateKey

            checkNotNull(privateKey) { "The given Private Key is null." }

            val signature: ByteArray = createSignatureFor(description, privateKey, headerBytes, payloadBytes)

            return DERToJOSE(signature)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    @Throws(SignatureGenerationException::class)
    override fun sign(contentBytes: ByteArray): ByteArray {
        try {
            val privateKey: ECPrivateKey? = keyProvider.privateKey

            checkNotNull(privateKey) { "The given Private Key is null." }

            val signature: ByteArray = createSignatureFor(description, privateKey, contentBytes)

            return DERToJOSE(signature)
        } catch (e: Exception) {
            throw SignatureGenerationException(this, e)
        }
    }

    @Suppress("ktlint:standard:function-naming")
    // Visible for testing
    @Throws(SignatureException::class)
    internal fun DERToJOSE(derSignature: ByteArray): ByteArray {
        // DER Structure: http://crypto.stackexchange.com/a/1797
        val derEncoded = derSignature[0].toInt() == 0x30 && derSignature.size != ecNumberSize * 2
        if (!derEncoded) {
            throw SignatureException("Invalid DER signature format.")
        }

        val joseSignature = ByteArray(ecNumberSize * 2)

        // Skip 0x30
        var offset = 1
        if (derSignature[1] == 0x81.toByte()) {
            // Skip sign
            offset++
        }

        // Convert to unsigned. Should match DER length - offset
        val encodedLength = derSignature[offset++].toInt() and 0xff
        if (encodedLength != derSignature.size - offset) {
            throw SignatureException("Invalid DER signature format.")
        }

        // Skip 0x02
        offset++

        // Obtain R number length (Includes padding) and skip it
        val rlength = derSignature[offset++].toInt()
        if (rlength > ecNumberSize + 1) {
            throw SignatureException("Invalid DER signature format.")
        }
        val rpadding = ecNumberSize - rlength
        // Retrieve R number
        derSignature.copyInto(
            joseSignature,
            max(rpadding, 0),
            offset + max(-rpadding, 0),
            offset + max(-rpadding, 0) + rlength + min(rpadding, 0),
        )

        // Skip R number and 0x02
        offset += rlength + 1

        // Obtain S number length. (Includes padding)
        val slength = derSignature[offset++].toInt()
        if (slength > ecNumberSize + 1) {
            throw SignatureException("Invalid DER signature format.")
        }
        val spadding = ecNumberSize - slength
        // Retrieve R number

        derSignature.copyInto(
            joseSignature,
            ecNumberSize + max(spadding, 0),
            offset + max(-spadding, 0),
            offset + max(-spadding, 0) + slength + min(spadding, 0),
        )

        return joseSignature
    }

    /**
     * Added check for extra protection against CVE-2022-21449.
     * This method ensures the signature's structure is as expected.
     *
     * @param joseSignature is the signature from the JWT
     * @param publicKey     public key used to verify the JWT
     * @throws SignatureException if the signature's structure is not as per expectation
     */
    // Visible for testing
    @Throws(SignatureException::class)
    internal fun validateSignatureStructure(joseSignature: ByteArray, publicKey: ECPublicKey) {
        // check signature length, moved this check from JOSEToDER method
        if (joseSignature.size != ecNumberSize * 2) {
            throw SignatureException("Invalid JOSE signature format.")
        }

        if (joseSignature.isAllZeros) {
            throw SignatureException("Invalid signature format.")
        }

        // get R
        val rBytes = ByteArray(ecNumberSize)
        joseSignature.copyInto(
            rBytes,
            0,
            0,
            ecNumberSize,
        )

        if (rBytes.isAllZeros) {
            throw SignatureException("Invalid signature format.")
        }

        // get S
        val sBytes = ByteArray(ecNumberSize)
        joseSignature.copyInto(
            sBytes,
            0,
            ecNumberSize,
            ecNumberSize * 2,
        )

        if (sBytes.isAllZeros) {
            throw SignatureException("Invalid signature format.")
        }

        // moved this check from JOSEToDER method
        val rPadding = countPadding(joseSignature, 0, ecNumberSize)
        val sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.size)
        val rLength = ecNumberSize - rPadding
        val sLength = ecNumberSize - sPadding

        val length = 2 + rLength + 2 + sLength
        if (length > 255) {
            throw SignatureException("Invalid JOSE signature format.")
        }

        verifySignature(publicKey, rBytes, sBytes)
    }

    @Suppress("ktlint:standard:function-naming")
    // Visible for testing
    @Throws(SignatureException::class)
    internal fun JOSEToDER(joseSignature: ByteArray): ByteArray {
        // Retrieve R and S number's length and padding.
        val rPadding = countPadding(joseSignature, 0, ecNumberSize)
        val sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.size)
        val rLength = ecNumberSize - rPadding
        val sLength = ecNumberSize - sPadding

        val length = 2 + rLength + 2 + sLength

        val derSignature: ByteArray
        var offset: Int
        if (length > 0x7f) {
            derSignature = ByteArray(3 + length)
            derSignature[1] = 0x81.toByte()
            offset = 2
        } else {
            derSignature = ByteArray(2 + length)
            offset = 1
        }

        // DER Structure: http://crypto.stackexchange.com/a/1797
        // Header with signature length info
        derSignature[0] = 0x30.toByte()
        derSignature[offset++] = (length and 0xff).toByte()

        // Header with "min R" number length
        derSignature[offset++] = 0x02.toByte()
        derSignature[offset++] = rLength.toByte()

        // R number
        if (rPadding < 0) {
            // Sign
            derSignature[offset++] = 0x00.toByte()
            joseSignature.copyInto(
                derSignature,
                offset,
                0,
                ecNumberSize,
            )

            offset += ecNumberSize
        } else {
            val copyLength: Int = min(ecNumberSize, rLength)
            joseSignature.copyInto(
                derSignature,
                offset,
                rPadding,
                rPadding + copyLength,
            )
            offset += copyLength
        }

        // Header with "min S" number length
        derSignature[offset++] = 0x02.toByte()
        derSignature[offset++] = sLength.toByte()

        // S number
        if (sPadding < 0) {
            // Sign
            derSignature[offset++] = 0x00.toByte()

            joseSignature.copyInto(
                derSignature,
                offset,
                ecNumberSize,
                ecNumberSize + ecNumberSize,
            )
        } else {
            joseSignature.copyInto(
                derSignature,
                offset,
                ecNumberSize + sPadding,
                ecNumberSize + sPadding + min(ecNumberSize, sLength),
            )
        }

        return derSignature
    }

    private fun countPadding(bytes: ByteArray, fromIndex: Int, toIndex: Int): Int {
        var padding = 0
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding].toInt() == 0) {
            padding++
        }
        return if ((bytes[fromIndex + padding].toInt() and 0xff) > 0x7f) padding - 1 else padding
    }

    internal companion object {
        // Visible for testing
        internal fun providerForKeys(publicKey: ECPublicKey?, privateKey: ECPrivateKey?): ECDSAKeyProvider {
            require(!(publicKey == null && privateKey == null)) { "Both provided Keys cannot be null." }

            return object : ECDSAKeyProvider {
                override fun getPublicKeyById(keyId: String?): ECPublicKey? = publicKey
                override val privateKey: ECPrivateKey? get() = privateKey
                override val privateKeyId: String? get() = null
            }
        }

        private val ByteArray.isAllZeros: Boolean
            get() = all { it.toInt() == 0 }
    }
}

internal expect fun verifySignature(publicKey: ECPublicKey, rBytes: ByteArray, sBytes: ByteArray)
