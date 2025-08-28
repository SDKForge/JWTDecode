package dev.sdkforge.jwt.decode.domain

class DecodeException : RuntimeException {
    internal constructor(message: String?) : super(message)
    internal constructor(message: String?, cause: Throwable?) : super(message, cause)
}
