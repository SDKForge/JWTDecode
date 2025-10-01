@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import dev.sdkforge.jwt.decode.domain.exception.JWTVerificationException

/**
 * Used to verify the JWT for its signature and claims. Instances are created using [Verification].
 */
interface JWTVerifier {
    /**
     * Performs the verification against the given Token.
     *
     * @param token to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    @Throws(JWTVerificationException::class)
    fun verify(token: String): DecodedJWT

    /**
     * Performs the verification against the given [DecodedJWT].
     *
     * @param jwt to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    @Throws(JWTVerificationException::class)
    fun verify(jwt: DecodedJWT): DecodedJWT
}
