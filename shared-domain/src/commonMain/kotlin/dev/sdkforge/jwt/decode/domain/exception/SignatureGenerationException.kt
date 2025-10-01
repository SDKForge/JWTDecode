@file:Suppress("ktlint:standard:class-signature")

package dev.sdkforge.jwt.decode.domain.exception

import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm

/**
 * The exception that is thrown when signature is not able to be generated.
 */
class SignatureGenerationException(algorithm: Algorithm, cause: Throwable) : JWTCreationException(
    message = "The Token's Signature couldn't be generated when signing using the Algorithm: $algorithm",
    cause = cause,
)
