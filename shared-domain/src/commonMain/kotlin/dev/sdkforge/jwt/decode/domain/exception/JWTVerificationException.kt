package dev.sdkforge.jwt.decode.domain.exception

/**
 * Parent to all the exception thrown while verifying a JWT.
 */
open class JWTVerificationException internal constructor(message: String?, cause: Throwable?) : RuntimeException(message, cause) {
    constructor(message: String?) : this(message, null)
}
