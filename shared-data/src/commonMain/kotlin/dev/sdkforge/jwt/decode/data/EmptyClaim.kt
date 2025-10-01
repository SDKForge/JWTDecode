@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy

/**
 * The EmptyClaim class is a Claim implementation that returns null when any of it's methods it's called.
 */
@OptIn(ExperimentalTime::class)
internal data object EmptyClaim : Claim {
    override val isNull: Boolean = false
    override val isMissing: Boolean = true
    override fun asBoolean(): Boolean? = null
    override fun asInt(): Int? = null
    override fun asLong(): Long? = null
    override fun asDouble(): Double? = null
    override fun asString(): String? = null
    override fun asInstant(): Instant? = null

    @Throws(JWTDecodeException::class)
    override fun <T> asList(deserializer: DeserializationStrategy<T>): List<T> = emptyList()

    @Throws(JWTDecodeException::class)
    override fun <T> asObject(deserializer: DeserializationStrategy<T>): T? = null
}
