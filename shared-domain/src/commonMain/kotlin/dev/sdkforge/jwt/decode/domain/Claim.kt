@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy

/**
 * The Claim class holds the value in a generic way so that it can be recovered in many representations.
 */
@OptIn(ExperimentalTime::class)
interface Claim {
    /**
     * Whether this Claim has a null value or not.
     * If the claim is not present, it will return false hence checking [Claim.isMissing] is advised as well
     *
     * @return whether this Claim has a null value or not.
     */
    val isNull: Boolean

    /**
     * Can be used to verify whether the Claim is found or not.
     * This will be true even if the Claim has `null` value associated to it.
     *
     * @return whether this Claim is present or not
     */
    val isMissing: Boolean

    /**
     * Get this Claim as a Boolean.
     * If the value isn't of type Boolean or it can't be converted to a Boolean, `null` will be returned.
     *
     * @return the value as a Boolean or null.
     */
    fun asBoolean(): Boolean?

    /**
     * Get this Claim as an Integer.
     * If the value isn't of type Integer or it can't be converted to an Integer, `null` will be returned.
     *
     * @return the value as an Integer or null.
     */
    fun asInt(): Int?

    /**
     * Get this Claim as an Long.
     * If the value isn't of type Long or it can't be converted to a Long, `null` will be returned.
     *
     * @return the value as an Long or null.
     */
    fun asLong(): Long?

    /**
     * Get this Claim as a Double.
     * If the value isn't of type Double or it can't be converted to a Double, `null` will be returned.
     *
     * @return the value as a Double or null.
     */
    fun asDouble(): Double?

    /**
     * Get this Claim as a String.
     * If the value isn't of type String, `null` will be returned. For a String representation of non-textual
     * claim types, clients can call `toString()`.
     *
     * @return the value as a String or null if the underlying value is not a string.
     */
    fun asString(): String?

    /**
     * Get this Claim as an Instant.
     * If the value can't be converted to an Instant, `null` will be returned.
     *
     * @return the value as an Instant or null.
     */
    fun asInstant(): Instant?

    /**
     * Get this Claim as a List of type T.
     * If the value isn't an Array, an empty List will be returned.
     *
     * @return the value as a List or an empty List.
     * @throws JWTDecodeException if the values inside the List can't be converted to a class T.
     */
    @Throws(JWTDecodeException::class)
    fun <T> asList(deserializer: DeserializationStrategy<T>): List<T>

    /**
     * Get this Claim as a Object of type T.
     * This method will return null if [Claim.isMissing] or [Claim.isNull] is true
     *
     * @return the value as a Object of type T or null.
     * @throws JWTDecodeException if the value can't be converted to a class T.
     */
    @Throws(JWTDecodeException::class)
    fun <T> asObject(deserializer: DeserializationStrategy<T>): T?

    companion object {
        /**
         * Contains constants representing the name of the Registered Claim Names as defined in Section 4.1 of
         * [RFC 7529](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)
         */
        object Registered {
            /**
             * The "iss" (issuer) claim identifies the principal that issued the JWT.
             * Refer RFC 7529 [Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
             */
            const val ISSUER: String = "iss"

            /**
             * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
             * Refer RFC 7529 [Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)
             */
            const val SUBJECT: String = "sub"

            /**
             * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
             * Refer RFC 7529 [Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
             */
            const val AUDIENCE: String = "aud"

            /**
             * The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be
             * accepted for processing.
             * Refer RFC 7529 [Section 4.1.4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
             */
            const val EXPIRES_AT: String = "exp"

            /**
             * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
             * Refer RFC 7529 [Section 4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
             */
            const val NOT_BEFORE: String = "nbf"

            /**
             * The "iat" (issued at) claim identifies the time at which the JWT was issued.
             * Refer RFC 7529 [Section 4.1.6](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
             */
            const val ISSUED_AT: String = "iat"

            /**
             * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
             * Refer RFC 7529 [Section 4.1.7](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
             */
            const val JWT_ID: String = "jti"
        }
    }
}
