@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import kotlin.io.encoding.Base64

internal data object NoneAlgorithm :
    Algorithm(
        name = "none",
        description = "none",
    ),
    VerificationAlgorithm,
    SigningAlgorithm {

    @Throws(SignatureVerificationException::class)
    override fun verify(jwt: DecodedJWT) {
        try {
            val signatureBytes: ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(jwt.signature)

            if (signatureBytes.isNotEmpty()) {
                throw SignatureVerificationException(this)
            }
        } catch (e: IllegalArgumentException) {
            throw SignatureVerificationException(this, e)
        }
    }

    @Throws(SignatureGenerationException::class)
    override fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): ByteArray = ByteArray(0)

    @Throws(SignatureGenerationException::class)
    override fun sign(contentBytes: ByteArray): ByteArray = ByteArray(0)
}
