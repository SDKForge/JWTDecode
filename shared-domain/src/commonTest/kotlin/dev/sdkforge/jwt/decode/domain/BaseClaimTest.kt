package dev.sdkforge.jwt.decode.domain

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.ExperimentalTime
import kotlinx.serialization.builtins.serializer

@OptIn(ExperimentalTime::class)
class BaseClaimTest {

    private val claim: BaseClaim = BaseClaim()

    @Test
    fun shouldGetAsBoolean() {
        assertNull(claim.asBoolean())
    }

    @Test
    fun shouldGetAsInt() {
        assertNull(claim.asInt())
    }

    @Test
    fun shouldGetAsLong() {
        assertNull(claim.asLong())
    }

    @Test
    fun shouldGetAsDouble() {
        assertNull(claim.asDouble())
    }

    @Test
    fun shouldGetAsString() {
        assertNull(claim.asString())
    }

    @Test
    fun shouldGetAsDate() {
        assertNull(claim.asDate())
    }

    @Test
    fun shouldGetAsList() {
        assertNotNull(claim.asList(Unit.serializer()))
        assertContentEquals(emptyList(), claim.asList(Unit.serializer()))
    }

    @Test
    fun shouldGetAsObject() {
        assertNull(claim.asObject(Unit.serializer()))
    }
}
