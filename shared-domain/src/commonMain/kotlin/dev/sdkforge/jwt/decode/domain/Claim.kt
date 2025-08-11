@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable

/**
 * The Claim class holds the value in a generic way so that it can be recovered in many representations.
 */

@OptIn(ExperimentalTime::class)
@Serializable(with = ClaimAsStringSerializer::class)
interface Claim {
    /**
     * Get this Claim as a Boolean.
     * If the value isn't of type Boolean or it can't be converted to a Boolean, null will be returned.
     *
     * @return the value as a Boolean or null.
     */
    fun asBoolean(): Boolean?

    /**
     * Get this Claim as an Integer.
     * If the value isn't of type Integer or it can't be converted to an Integer, null will be returned.
     *
     * @return the value as an Integer or null.
     */
    fun asInt(): Int?

    /**
     * Get this Claim as an Long.
     * If the value isn't of type Long or it can't be converted to an Long, null will be returned.
     *
     * @return the value as an Long or null.
     */
    fun asLong(): Long?

    /**
     * Get this Claim as a Double.
     * If the value isn't of type Double or it can't be converted to a Double, null will be returned.
     *
     * @return the value as a Double or null.
     */
    fun asDouble(): Double?

    /**
     * Get this Claim as a String.
     * If the value isn't of type String or it can't be converted to a String, null will be returned.
     *
     * @return the value as a String or null.
     */
    fun asString(): String?

    /**
     * Get this Claim as a Date.
     * If the value can't be converted to a Date, null will be returned.
     *
     * @return the value as a Date or null.
     */
    fun asDate(): Instant?

    /**
     * Get this Claim as a List of type T.
     * If the value isn't an Array, an empty List will be returned.
     *
     * @return the value as a List or an empty List.
     * @throws DecodeException if the values inside the List can't be converted to a class T.
     */
    @Throws(DecodeException::class)
    fun <T> asList(deserializer: DeserializationStrategy<T>): List<T>

    /**
     * Get this Claim as a Object of type T.
     * If the value isn't of type Object, null will be returned.
     *
     * @return the value as a Object of type T or null.
     * @throws DecodeException if the value can't be converted to a class T.
     */
    @Throws(DecodeException::class)
    fun <T> asObject(deserializer: DeserializationStrategy<T>): T?
}
