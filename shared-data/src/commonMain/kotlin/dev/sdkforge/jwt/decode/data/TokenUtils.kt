@file:Suppress("ktlint:standard:function-expression-body", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException

internal object TokenUtils {
    /**
     * Splits the given token on the "." chars into a String array with 3 parts.
     *
     * @param token the string to split.
     * @return the array representing the 3 parts of the token.
     * @throws JWTDecodeException if the Token doesn't have 3 parts.
     */
    @Throws(JWTDecodeException::class)
    fun splitToken(token: String?): Array<String> {
        if (token == null) {
            throw JWTDecodeException("The token is null.")
        }

        return token.split(delimiters = arrayOf(".")).toTypedArray().apply {
            if (size != 3) throw wrongNumberOfParts(size)
        }
    }

    private fun wrongNumberOfParts(partCount: Any): JWTDecodeException {
        return JWTDecodeException(
            message = "The token was expected to have 3 parts, but got $partCount.",
        )
    }
}
