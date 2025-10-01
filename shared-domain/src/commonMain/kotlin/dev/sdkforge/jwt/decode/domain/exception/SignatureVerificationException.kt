@file:Suppress("ktlint:standard:class-signature")

package dev.sdkforge.jwt.decode.domain.exception

import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm

/**
 * The exception that is thrown if the Signature verification fails.
 */
class SignatureVerificationException(algorithm: Algorithm, cause: Throwable?) : JWTVerificationException(
    message = "The Token's Signature resulted invalid when verified using the Algorithm: $algorithm",
    cause = cause,
) {
    constructor(algorithm: Algorithm) : this(algorithm = algorithm, cause = null)
}
