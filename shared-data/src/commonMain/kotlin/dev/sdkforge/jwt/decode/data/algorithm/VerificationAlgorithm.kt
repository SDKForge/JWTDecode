@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException

internal interface VerificationAlgorithm {
    /**
     * Verify the given token using this Algorithm instance.
     *
     * @param jwt the already decoded JWT that it's going to be verified.
     * @throws SignatureVerificationException if the Token's Signature is invalid,
     * meaning that it doesn't match the signatureBytes,
     * or if the Key is invalid.
     */
    @Throws(SignatureVerificationException::class)
    fun verify(jwt: DecodedJWT)
}
