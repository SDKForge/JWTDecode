package dev.sdkforge.jwt.decode.domain.exception

/**
 * The exception that will be thrown while verifying Claims of a JWT.
 */
open class InvalidClaimException internal constructor(message: String?) : JWTVerificationException(message)
