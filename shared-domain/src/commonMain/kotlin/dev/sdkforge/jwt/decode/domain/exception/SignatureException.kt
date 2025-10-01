package dev.sdkforge.jwt.decode.domain.exception

class SignatureException(message: String?, cause: Throwable?) : JWTVerificationException(message, cause) {
    constructor(message: String? = null) : this(message, null)
}
