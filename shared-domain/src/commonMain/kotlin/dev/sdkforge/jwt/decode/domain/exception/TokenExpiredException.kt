package dev.sdkforge.jwt.decode.domain.exception

import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The exception that is thrown if the token is expired.
 */
@OptIn(ExperimentalTime::class)
class TokenExpiredException(message: String, val expiredOn: Instant?) : JWTVerificationException(message)
