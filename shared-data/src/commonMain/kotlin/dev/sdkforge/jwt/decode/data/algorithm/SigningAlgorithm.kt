@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException

internal interface SigningAlgorithm {

    val signingKeyId: String?
        /**
         * Getter for the Id of the Private Key used to sign the tokens.
         * This is usually specified as the `kid` claim in the Header.
         *
         * @return the Key Id that identifies the Signing Key or null if it's not specified.
         */
        get() = null

    /**
     * Sign the given content using this Algorithm instance.
     *
     * @param headerBytes  an array of bytes representing the base64 encoded header content
     * to be verified against the signature.
     * @param payloadBytes an array of bytes representing the base64 encoded payload content
     * to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */
    @Throws(SignatureGenerationException::class)
    fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): ByteArray {
        // default implementation; keep around until sign(byte[]) method is removed
        val contentBytes = ByteArray(headerBytes.size + 1 + payloadBytes.size)

        headerBytes.copyInto(
            destination = contentBytes,
            destinationOffset = 0,
        )

        contentBytes[headerBytes.size] = '.'.code.toByte()

        payloadBytes.copyInto(
            destination = contentBytes,
            destinationOffset = headerBytes.size + 1,
        )

        return sign(contentBytes)
    }

    /**
     * Sign the given content using this Algorithm instance.
     * To get the correct JWT Signature, ensure the content is in the format {HEADER}.{PAYLOAD}
     *
     * @param contentBytes an array of bytes representing the base64 encoded content
     * to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */
    @Throws(SignatureGenerationException::class)
    fun sign(contentBytes: ByteArray): ByteArray
}
