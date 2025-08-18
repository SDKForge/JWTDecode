package dev.sdkforge.jwt.decode.domain

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.encodeToJsonElement

@OptIn(ExperimentalTime::class)
class ClaimImplTest {
    private val json = Json.Default

    @Test
    fun shouldGetBooleanValue() {
        val value: JsonElement = json.encodeToJsonElement(true)
        val claim = JsonClaim(value)

        assertNotNull(claim.asBoolean())
        assertEquals(true, claim.asBoolean())
    }

    @Test
    fun shouldGetNullBooleanIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asBoolean())
    }

    @Test
    fun shouldGetIntValue() {
        val value: JsonElement = json.encodeToJsonElement(123)
        val claim = JsonClaim(value)

        assertNotNull(claim.asInt())
        assertEquals(123, claim.asInt())
    }

    @Test
    fun shouldGetLongValue() {
        val value: JsonElement = json.encodeToJsonElement(123L)
        val claim = JsonClaim(value)

        assertNotNull(claim.asLong())
        assertEquals(123L, claim.asLong())
    }

    @Test
    fun shouldGetNullIntIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asInt())
    }

    @Test
    fun shouldGetNullLongIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asLong())
    }

    @Test
    fun shouldGetDoubleValue() {
        val value: JsonElement = json.encodeToJsonElement(1.5)
        val claim = JsonClaim(value)

        assertNotNull(claim.asDouble())
        assertEquals(1.5, claim.asDouble())
    }

    @Test
    fun shouldGetNullDoubleIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asDouble())
    }

    @Test
    fun shouldGetLargeDateValue() {
        val seconds: Long = Int.MAX_VALUE + 10000L
        val value: JsonElement = json.encodeToJsonElement(seconds)
        val claim = JsonClaim(value)

        val date: Instant? = claim.asDate()
        assertNotNull(date)
        assertEquals(seconds, date.epochSeconds)
        assertEquals(2147493647, date.epochSeconds)
    }

    @Test
    fun shouldGetDateValue() {
        val value: JsonElement = json.encodeToJsonElement("1476824844")
        val claim = JsonClaim(value)

        assertNotNull(claim.asDate())
        assertEquals(Instant.fromEpochSeconds(1476824844), claim.asDate())
    }

    @Test
    fun shouldGetNullDateIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asDate())
    }

    @Test
    fun shouldGetStringValue() {
        val value: JsonElement = json.encodeToJsonElement("string")
        val claim = JsonClaim(value)

        assertNotNull(claim.asString())
        assertEquals("string", claim.asString())
    }

    @Test
    fun shouldGetNullStringIfNotPrimitiveValue() {
        val value: JsonElement = json.encodeToJsonElement(Unit)
        val claim = JsonClaim(value)

        assertNull(claim.asString())
    }

    @Test
    fun shouldGetListValueOfCustomClass() {
        val value: JsonElement = json.encodeToJsonElement(listOf(UserPojo("George", 1), UserPojo("Mark", 2)))
        val claim = JsonClaim(value)

        assertNotNull(claim.asList<UserPojo>(UserPojo.serializer()))
        assertContentEquals(
            listOf(UserPojo("George", 1), UserPojo("Mark", 2)),
            claim.asList<UserPojo>(UserPojo.serializer()),
        )
    }

    @Test
    fun shouldGetListValue() {
        val value: JsonElement = json.encodeToJsonElement(listOf("string1", "string2"))
        val claim = JsonClaim(value)

        assertNotNull(claim.asList<String>(String.serializer()))
        assertContentEquals(
            listOf("string1", "string2"),
            claim.asList<String>(String.serializer()),
        )
    }

    @Test
    fun shouldGetEmptyListIfNullValue() {
        val value: JsonElement = json.encodeToJsonElement(null.orEmpty())
        val claim = JsonClaim(value)

        assertNotNull(claim.asList<String>(String.serializer()))
        assertContentEquals(
            emptyList(),
            claim.asList<String>(String.serializer()),
        )
    }

    @Test
    fun shouldGetEmptyListIfNonArrayValue() {
        val value: JsonElement = json.encodeToJsonElement(1)
        val claim = JsonClaim(value)

        assertNotNull(claim.asList<String>(String.serializer()))
        assertContentEquals(
            emptyList(),
            claim.asList<String>(String.serializer()),
        )
    }

    @Test
    fun shouldThrowIfListClassMismatch() {
        val value: JsonElement = json.encodeToJsonElement(arrayOf<String>("keys", "values"))
        val claim = JsonClaim(value)

        assertFailsWith<DecodeException> {
            claim.asList<UserPojo>(UserPojo.serializer())
        }
    }

    @Test
    fun shouldGetAsObject() {
        val data = UserPojo("George", 1)
        val userValue: JsonElement = json.encodeToJsonElement(data)
        val userClaim = JsonClaim(userValue)

        val intValue: JsonElement = json.encodeToJsonElement(1)
        val intClaim = JsonClaim(intValue)

        val booleanValue: JsonElement = json.encodeToJsonElement(true)
        val booleanClaim = JsonClaim(booleanValue)

        assertNotNull(userClaim.asObject<UserPojo>(UserPojo.serializer()))
        assertEquals(UserPojo("George", 1), userClaim.asObject<UserPojo>(UserPojo.serializer()))

        assertNotNull(intClaim.asObject<Int>(Int.serializer()))
        assertEquals(1, intClaim.asObject<Int>(Int.serializer()))

        assertNotNull(booleanClaim.asObject<Boolean>(Boolean.serializer()))
        assertEquals(true, booleanClaim.asObject<Boolean>(Boolean.serializer()))
    }

    @Test
    fun shouldGetNullObjectIfNullValue() {
        val claim = JsonClaim(JsonNull)

        assertNull(claim.asObject<UserPojo>(UserPojo.serializer()))
    }

    @Test
    fun shouldThrowIfObjectClassMismatch() {
        val value: JsonElement = json.encodeToJsonElement(1)
        val claim = JsonClaim(value)

        assertFailsWith<DecodeException> {
            claim.asObject<UserPojo>(UserPojo.serializer())
        }
    }
}
