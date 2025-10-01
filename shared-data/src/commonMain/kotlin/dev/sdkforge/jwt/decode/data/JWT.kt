@file:Suppress("ktlint:standard:function-expression-body", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.Verification
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException

data object JWT {
    /**
     * Decode a given Json Web Token.
     *
     * Note that this method **doesn't verify the token's signature!**
     * Use it only if you trust the token or if you have already verified it.
     *
     * @param token with jwt format as string.
     * @return a decoded JWT.
     * @throws dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException if any part of the token contained an invalid jwt
     * or JSON format of each of the jwt parts.
     */
    @Throws(JWTDecodeException::class)
    fun decode(token: String, parser: dev.sdkforge.jwt.decode.domain.JWTParser = JWTParser): DecodedJWT {
        return JWTDecoder(parser, token)
    }

    /**
     * Returns a [Verification] builder with the algorithm to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return [Verification] builder
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    fun require(algorithm: Algorithm): Verification {
        return JWTVerifier.init(algorithm)
    }

    /**
     * Returns a Json Web Token builder used to create and sign tokens.
     *
     * @return a token builder.
     */
    internal fun create(): JWTCreator.Builder {
        return JWTCreator.init()
    }
}
