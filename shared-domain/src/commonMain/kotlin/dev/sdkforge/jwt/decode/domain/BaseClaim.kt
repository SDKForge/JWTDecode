@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy

/**
 * The BaseClaim class is a Claim implementation that returns null when any of it's methods it's called.
 */
@OptIn(ExperimentalTime::class)
internal open class BaseClaim : Claim {
    override fun asBoolean(): Boolean? = null
    override fun asInt(): Int? = null
    override fun asLong(): Long? = null
    override fun asDouble(): Double? = null
    override fun asString(): String? = null
    override fun asDate(): Instant? = null

    @Throws(DecodeException::class)
    override fun <T> asList(deserializer: DeserializationStrategy<T>): List<T> = emptyList()

    @Throws(DecodeException::class)
    override fun <T> asObject(deserializer: DeserializationStrategy<T>): T? = null
}
