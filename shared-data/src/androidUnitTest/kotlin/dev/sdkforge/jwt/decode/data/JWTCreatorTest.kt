package dev.sdkforge.jwt.decode.data

import dev.sdkforge.crypto.domain.ec.asNativeECPrivateKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPrivateKey
import dev.sdkforge.jwt.decode.data.JsonMatcher.Companion.hasEntry
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA256
import dev.sdkforge.jwt.decode.data.algorithm.HMAC256
import dev.sdkforge.jwt.decode.data.algorithm.NONE
import dev.sdkforge.jwt.decode.data.algorithm.RSA256
import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.Header
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.provider.ECDSAKeyProvider
import dev.sdkforge.jwt.decode.domain.provider.RSAKeyProvider
import io.mockk.every
import io.mockk.junit4.MockKRule
import io.mockk.mockk
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.util.*
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Rule

@OptIn(ExperimentalTime::class)
class JWTCreatorTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    @Test
    fun shouldAddHeaderClaim() {
        val instant = Instant.fromEpochSeconds(123000L)

        val list = listOf<Any?>(instant)
        val map = buildMap<String, Any?> {
            this["instant"] = instant
        }

        val expectedSerializedList = listOf<Any?>(instant.epochSeconds)
        val expectedSerializedMap = buildMap<String?, Any?> {
            this["instant"] = instant.epochSeconds
        }

        val header = buildMap<String, Any?> {
            this["string"] = "string"
            this["int"] = 42
            this["long"] = 4200000000L
            this["double"] = 123.123
            this["bool"] = true
            this["instant"] = instant
            this["list"] = list
            this["map"] = map
        }

        val signed = JWTCreator.init()
            .withHeader(header)
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("string", "string").matches(headerJson))
        assertTrue(hasEntry("int", 42).matches(headerJson))
        assertTrue(hasEntry("long", 4200000000L).matches(headerJson))
        assertTrue(hasEntry("double", 123.123).matches(headerJson))
        assertTrue(hasEntry("bool", true).matches(headerJson))
        assertTrue(hasEntry("instant", 123).matches(headerJson))
        assertTrue(hasEntry("list", expectedSerializedList).matches(headerJson))
        assertTrue(hasEntry("map", expectedSerializedMap).matches(headerJson))
    }

    @Test
    fun shouldReturnBuilderIfNullMapIsProvided() {
        val nullMap: Map<String, Any?>? = null
        val nullString: String? = null

        JWTCreator.init()
            .withHeader(nullMap)
            .withHeader(nullString)
            .sign(Algorithm.HMAC256("secret"))
    }

    @Test
    fun shouldSupportJsonValueHeaderWithNestedDataStructure() {
        val stringClaim = "someClaim"
        val intClaim = 1
        val nestedListClaims = listOf("1", "2")
        val claimsJson = "{\"stringClaim\": \"someClaim\", \"intClaim\": 1, \"nestedClaim\": { \"listClaim\": [ \"1\", \"2\" ]}}"

        val jwt = JWTCreator.init()
            .withHeader(claimsJson)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        val headerJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[0]).decodeToString()

        assertTrue(hasEntry("stringClaim", stringClaim).matches(headerJson))
        assertTrue(hasEntry("intClaim", intClaim).matches(headerJson))
        assertTrue(hasEntry("listClaim", nestedListClaims).matches(headerJson))
    }

    @Test
    fun shouldFailWithIllegalArgumentExceptionForInvalidJsonForHeaderClaims() {
        val t = assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withHeader("{ invalidJson }")
                .sign(Algorithm.HMAC256("secret"))
        }

        assertEquals("Invalid header JSON", t.message)
    }

    @Test
    fun shouldOverwriteExistingHeaderIfHeaderMapContainsTheSameKey() {
        val header = buildMap<String, Any?> {
            this[Header.Companion.Params.KEY_ID] = "xyz"
        }

        val signed = JWTCreator.init()
            .withKeyId("abc")
            .withHeader(header)
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry(Header.Companion.Params.KEY_ID, "xyz").matches(headerJson))
    }

    @Test
    fun shouldOverwriteExistingHeadersWhenSettingSameHeaderKey() {
        val header = buildMap<String, Any?> {
            this[Header.Companion.Params.KEY_ID] = "xyz"
        }

        val signed = JWTCreator.init()
            .withHeader(header)
            .withKeyId("abc")
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry(Header.Companion.Params.KEY_ID, "abc").matches(headerJson))
    }

    @Test
    fun shouldRemoveHeaderIfTheValueIsNull() {
        val header = buildMap<String, Any?> {
            this[Header.Companion.Params.KEY_ID] = null
            this["test2"] = "isSet"
        }

        val signed = JWTCreator.init()
            .withKeyId("test")
            .withHeader(header)
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(JsonMatcher.isNotPresent(Header.Companion.Params.KEY_ID).matches(headerJson))
        assertTrue(hasEntry("test2", "isSet").matches(headerJson))
    }

    @Test
    fun shouldAddKeyId() {
        val signed = JWTCreator.init()
            .withKeyId("56a8bd44da435300010000015f5ed")
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[0]).decodeToString()

        assertTrue(hasEntry("kid", "56a8bd44da435300010000015f5ed").matches(headerJson))
    }

    @Test
    fun shouldAddKeyIdIfAvailableFromRSAAlgorithms() {
        val provider: RSAKeyProvider = mockk {
            every { privateKeyId } returns "my-key-id"
            every { privateKey } returns readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_RSA, "RSA").asNativeRSAPrivateKey
        }

        val signed = JWTCreator.init()
            .sign(Algorithm.RSA256(provider))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("kid", "my-key-id").matches(headerJson))
    }

    @Test
    fun shouldNotOverwriteKeyIdIfAddedFromRSAAlgorithms() {
        val provider: RSAKeyProvider = mockk {
            every { privateKeyId } returns "my-key-id"
            every { privateKey } returns readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_RSA, "RSA").asNativeRSAPrivateKey
        }

        val signed = JWTCreator.init()
            .withKeyId("real-key-id")
            .sign(Algorithm.RSA256(provider))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("kid", "my-key-id").matches(headerJson))
    }

    @Test
    fun shouldAddKeyIdIfAvailableFromECDSAAlgorithms() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKeyId } returns "my-key-id"
            every { privateKey } returns readPrivateKey<ECPrivateKey>(PRIVATE_KEY_EC_256, "EC").asNativeECPrivateKey
        }

        val signed = JWTCreator.init()
            .sign(Algorithm.ECDSA256(provider))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("kid", "my-key-id").matches(headerJson))
    }

    @Test
    fun shouldNotOverwriteKeyIdIfAddedFromECDSAAlgorithms() {
        val provider: ECDSAKeyProvider = mockk {
            every { privateKeyId } returns "my-key-id"
            every { privateKey } returns readPrivateKey<ECPrivateKey>(PRIVATE_KEY_EC_256, "EC").asNativeECPrivateKey
        }

        val signed = JWTCreator.init()
            .withKeyId("real-key-id")
            .sign(Algorithm.ECDSA256(provider))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("kid", "my-key-id").matches(headerJson))
    }

    @Test
    fun shouldAddIssuer() {
        val signed = JWTCreator.init()
            .withIssuer("auth0")
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJpc3MiOiJhdXRoMCJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddSubject() {
        val signed = JWTCreator.init()
            .withSubject("1234567890")
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJzdWIiOiIxMjM0NTY3ODkwIn0", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddAudience() {
        val signed = JWTCreator.init()
            .withAudience("Mark")
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJhdWQiOiJNYXJrIn0", TokenUtils.splitToken(signed)[1])

        val signedArr = JWTCreator.init()
            .withAudience("Mark", "David")
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19", TokenUtils.splitToken(signedArr)[1])
    }

    @Test
    fun shouldAddExpiresAt() {
        val signed = JWTCreator.init()
            .withExpiresAt(Instant.fromEpochMilliseconds(1477592000))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJleHAiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddExpiresAtInstant() {
        val signed = JWTCreator.init()
            .withExpiresAt(Instant.fromEpochSeconds(1477592))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJleHAiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddNotBefore() {
        val signed = JWTCreator.init()
            .withNotBefore(Instant.fromEpochMilliseconds(1477592000))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJuYmYiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddNotBeforeInstant() {
        val signed = JWTCreator.init()
            .withNotBefore(Instant.fromEpochSeconds(1477592))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJuYmYiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddIssuedAt() {
        val signed = JWTCreator.init()
            .withIssuedAt(Instant.fromEpochMilliseconds(1477592000))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJpYXQiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddIssuedAtInstant() {
        val signed = JWTCreator.init()
            .withIssuedAt(Instant.fromEpochSeconds(1477592))
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJpYXQiOjE0Nzc1OTJ9", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldAddJWTId() {
        val signed = JWTCreator.init()
            .withJWTId("jwt_id_123")
            .sign(Algorithm.HMAC256("secret"))

        assertEquals("eyJqdGkiOiJqd3RfaWRfMTIzIn0", TokenUtils.splitToken(signed)[1])
    }

    @Test
    fun shouldSetCorrectAlgorithmInTheHeader() {
        val signed = JWTCreator.init()
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("alg", "HS256").matches(headerJson))
    }

    @Test
    fun shouldSetDefaultTypeInTheHeader() {
        val signed = JWTCreator.init()
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.decode(parts[0]).decodeToString()

        assertTrue(hasEntry("typ", "JWT").matches(headerJson))
    }

    @Test
    fun shouldSetCustomTypeInTheHeader() {
        val header = Collections.singletonMap<String, Any?>("typ", "passport")
        val signed = JWTCreator.init()
            .withHeader(header)
            .sign(Algorithm.HMAC256("secret"))

        val parts = signed.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val headerJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[0]).decodeToString()

        assertTrue(hasEntry("typ", "passport").matches(headerJson))
    }

    @Test
    fun shouldSetEmptySignatureIfAlgorithmIsNone() {
        val signed = JWTCreator.init().sign(Algorithm.NONE)

        assertEquals("", TokenUtils.splitToken(signed)[2])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeString() {
        val jwt = JWTCreator.init()
            .withClaim("name", "value")
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjoidmFsdWUifQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeInteger() {
        val jwt = JWTCreator.init()
            .withClaim("name", 123)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjoxMjN9", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeLong() {
        val jwt = JWTCreator.init()
            .withClaim("name", Long.MAX_VALUE)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc1ODA3fQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeDouble() {
        val jwt = JWTCreator.init()
            .withClaim("name", 23.45)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjoyMy40NX0", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeBoolean() {
        val jwt = JWTCreator.init()
            .withClaim("name", true)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjp0cnVlfQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeDate() {
        val date = Instant.fromEpochMilliseconds(1478891521000L)
        val jwt = JWTCreator.init()
            .withClaim("name", date)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjoxNDc4ODkxNTIxfQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeDateInstant() {
        val instant = Instant.fromEpochSeconds(1478891521)
        val jwt = JWTCreator.init()
            .withClaim("name", instant)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjoxNDc4ODkxNTIxfQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomArrayClaimOfTypeString() {
        val jwt = JWTCreator.init()
            .withArrayClaim("name", arrayOf("text", "123", "true"))
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19", parts[1])
    }

    @Test
    fun shouldAcceptCustomArrayClaimOfTypeInteger() {
        val jwt = JWTCreator.init()
            .withArrayClaim("name", arrayOf<Int?>(1, 2, 3))
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjpbMSwyLDNdfQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomArrayClaimOfTypeLong() {
        val jwt = JWTCreator.init()
            .withArrayClaim("name", arrayOf(1L, 2L, 3L))
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJuYW1lIjpbMSwyLDNdfQ", parts[1])
    }

    @Test
    fun shouldAcceptCustomClaimOfTypeMap() {
        val data = buildMap<String, Any?> {
            this["test1"] = "abc"
            this["test2"] = "def"
        }

        val jwt = JWTCreator.init()
            .withClaim("data", data)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        assertEquals("eyJkYXRhIjp7InRlc3QxIjoiYWJjIiwidGVzdDIiOiJkZWYifX0", parts[1])
    }

    @Test
    fun shouldRefuseCustomClaimOfTypeUserPojo() {
        val data = buildMap<String, Any?> {
            this["test1"] = UserPojo("Michael", 255)
        }

        assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withClaim("pojo", data)
                .sign(Algorithm.HMAC256("secret"))
        }
    }

    @Test
    fun shouldAcceptCustomMapClaimOfBasicObjectTypes() {
        val data = buildMap<String, Any?> {
            // simple types
            this["string"] = "abc"
            this["integer"] = 1
            this["long"] = Long.MAX_VALUE
            this["double"] = 123.456
            this["instant"] = Instant.fromEpochSeconds(123)
            this["boolean"] = true

            // array types
            this["intArray"] = arrayOf(3, 5)
            this["longArray"] = arrayOf(Long.MAX_VALUE, Long.MIN_VALUE)
            this["stringArray"] = arrayOf("string")

            this["list"] = listOf("a", "b", "c")
            this["map"] = mapOf<String, Any?>("subKey" to "subValue")
        }

        val jwt = JWTCreator.init()
            .withClaim("data", data)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        val body = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()
        val map = JWTParser.JSON.decodeFromString<Map<String, JsonObject>>(body)["data"] as Map<String, JsonElement>

        assertEquals(map["string"]?.jsonPrimitive?.content, "abc")
        assertEquals(map["integer"]?.jsonPrimitive?.int, 1)
        assertEquals(map["long"]?.jsonPrimitive?.long, Long.MAX_VALUE)
        assertEquals(map["double"]?.jsonPrimitive?.double, 123.456)

        assertEquals(map["instant"]?.jsonPrimitive?.int, 123)
        assertEquals(map["boolean"]?.jsonPrimitive?.boolean, true)

        // array types
        assertEquals(map["intArray"]?.jsonArray[0]?.jsonPrimitive?.int, 3)
        assertEquals(map["intArray"]?.jsonArray[1]?.jsonPrimitive?.int, 5)
        assertEquals(map["longArray"]?.jsonArray[0]?.jsonPrimitive?.long, Long.MAX_VALUE)
        assertEquals(map["longArray"]?.jsonArray[1]?.jsonPrimitive?.long, Long.MIN_VALUE)
        assertEquals(map["stringArray"]?.jsonArray[0]?.jsonPrimitive?.content, "string")

        // list
        assertEquals(map["list"]?.jsonArray[0]?.jsonPrimitive?.content, "a")
        assertEquals(map["list"]?.jsonArray[1]?.jsonPrimitive?.content, "b")
        assertEquals(map["list"]?.jsonArray[2]?.jsonPrimitive?.content, "c")

        assertEquals(map["map"]?.jsonObject?.get("subKey")?.jsonPrimitive?.content, "subValue")
    }

    @Test
    fun shouldAcceptCustomListClaimOfBasicObjectTypes() {
        val data = buildList {
            // simple types
            add("abc")
            add(1)
            add(Long.MAX_VALUE)
            add(123.456)
            add(Instant.fromEpochSeconds(123))
            add(true)

            // array types
            add(arrayOf(3, 5))
            add(arrayOf(Long.MAX_VALUE, Long.MIN_VALUE))
            add(arrayOf("string"))

            add(listOf("a", "b", "c"))

            add(mapOf<String, Any?>("subKey" to "subValue"))
        }

        val jwt = JWTCreator.init()
            .withClaim("data", data)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        val body = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        val list = JWTParser.JSON.decodeFromString<Map<String, JsonArray>>(body)["data"] as List<JsonElement>

        assertEquals(list[0].jsonPrimitive.content, "abc")
        assertEquals(list[1].jsonPrimitive.int, 1)
        assertEquals(list[2].jsonPrimitive.long, Long.MAX_VALUE)
        assertEquals(list[3].jsonPrimitive.double, 123.456)
        assertEquals(list[4].jsonPrimitive.int, 123)
        assertEquals(list[5].jsonPrimitive.boolean, true)

        // array types
        assertEquals(list[6].jsonArray[0].jsonPrimitive.int, 3)
        assertEquals(list[6].jsonArray[1].jsonPrimitive.int, 5)
        assertEquals(list[7].jsonArray[0].jsonPrimitive.long, Long.MAX_VALUE)
        assertEquals(list[7].jsonArray[1].jsonPrimitive.long, Long.MIN_VALUE)
        assertEquals(list[8].jsonArray[0].jsonPrimitive.content, "string")

        // list
        assertEquals(list[9].jsonArray[0].jsonPrimitive.content, "a")
        assertEquals(list[9].jsonArray[1].jsonPrimitive.content, "b")
        assertEquals(list[9].jsonArray[2].jsonPrimitive.content, "c")

        assertEquals(list[10].jsonObject["subKey"]?.jsonPrimitive?.content, "subValue")
    }

    @Test
    fun shouldAcceptCustomClaimForNullListItem() {
        val data = buildMap<String, Any?> {
            this["test1"] = listOf("a", null, "c")
        }

        JWTCreator.init()
            .withClaim("pojo", data)
            .sign(Algorithm.HMAC256("secret"))
    }

    @Test
    fun shouldRefuseCustomListClaimForUnknownListElement() {
        val list = listOf<Any?>(UserPojo(name = "Michael", id = 255))

        assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withClaim("list", list)
                .sign(Algorithm.HMAC256("secret"))
        }
    }

    @Test
    fun shouldRefuseCustomListClaimForUnknownListElementWrappedInAMap() {
        val list = listOf<Any?>(UserPojo(name = "Michael", id = 255))

        buildMap<String?, Any?> {
            this["someList"] = list
        }

        assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withClaim("list", list)
                .sign(Algorithm.HMAC256("secret"))
        }
    }

    @Test
    fun shouldAcceptCustomListClaimForUnknownArrayType() {
        val list: MutableList<Any?> = ArrayList<Any?>()
        list.add(arrayOf<Any>("test"))

        JWTCreator.init()
            .withClaim("list", list)
            .sign(Algorithm.HMAC256("secret"))
    }

    @Test
    fun withPayloadShouldAddBasicClaim() {
        val payload = buildMap<String, Any?> {
            this["asd"] = 123
        }

        val jwt = JWTCreator.init()
            .withPayload(payload)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry("asd", 123).matches(payloadJson))
    }

    @Test
    fun withPayloadShouldCreateJwtWithEmptyBodyIfPayloadNull() {
        val nullString: String? = null

        val jwt = JWTCreator.init()
            .withPayload(nullString)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertEquals("{}", payloadJson)
    }

    @Test
    fun withPayloadShouldOverwriteExistingClaimIfPayloadMapContainsTheSameKey() {
        val payload = buildMap<String, Any?> {
            this[Header.Companion.Params.KEY_ID] = "xyz"
        }

        val jwt = JWTCreator.init()
            .withKeyId("abc")
            .withPayload(payload)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry(Header.Companion.Params.KEY_ID, "xyz").matches(payloadJson))
    }

    @Test
    fun shouldOverwriteExistingPayloadWhenSettingSamePayloadKey() {
        val payload = buildMap<String, Any?> {
            this[Claim.Companion.Registered.ISSUER] = "xyz"
        }

        val jwt = JWTCreator.init()
            .withPayload(payload)
            .withIssuer("abc")
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry(Claim.Companion.Registered.ISSUER, "abc").matches(payloadJson))
    }

    @Test
    fun withPayloadShouldNotAllowCustomType() {
        val payload = buildMap<String, Any?> {
            this["entry"] = "value"
            this["pojo"] = UserPojo("name", 42)
        }

        val t = assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"))
        }

        assertEquals("Claim values must only be of types Map, List, Boolean, Int, Long, Double, String, Instant, and Null", t.message)
    }

    @Test
    fun withPayloadShouldAllowNullListItems() {
        val payload = buildMap<String, Any?> {
            this["list"] = listOf("item1", null, "item2")
        }

        val jwt = JWTCreator.init()
            .withPayload(payload)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry("list", listOf("item1", null, "item2")).matches(payloadJson))
    }

    @Test
    fun withPayloadShouldNotAllowListWithCustomType() {
        val payload = buildMap<String, Any?> {
            this["list"] = listOf<Any?>(
                "item1",
                UserPojo("name", 42),
            )
        }

        val t = assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"))
        }

        assertEquals("Claim values must only be of types Map, List, Boolean, Int, Long, Double, String, Instant, and Null", t.message)
    }

    @Test
    fun withPayloadShouldNotAllowMapWithCustomType() {
        val payload = buildMap<String, Any?> {
            this["entry"] = "value"
            this["map"] = Collections.singletonMap(
                "pojo",
                UserPojo("name", 42),
            )
        }

        val t = assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"))
        }

        assertEquals("Claim values must only be of types Map, List, Boolean, Int, Long, Double, String, Instant, and Null", t.message)
    }

    @Test
    fun withPayloadShouldAllowNestedSupportedTypes() {
        /*
        JWT:
        {
          "stringClaim": "string",
          "intClaim": 41,
          "listClaim": [
            1, 2, {
              "nestedObjKey": true
            }
          ],
          "objClaim": {
            "objKey": ["nestedList1", "nestedList2"]
          }
        }
         */

        val listClaim = listOf(1, 2, Collections.singletonMap("nestedObjKey", "nestedObjValue"))
        val mapClaim = buildMap<String, Any?> {
            this["objKey"] = mutableListOf("nestedList1", true)
        }

        val payload = buildMap<String, Any?> {
            this["stringClaim"] = "string"
            this["intClaim"] = 41
            this["listClaim"] = listClaim
            this["objClaim"] = mapClaim
        }

        val jwt = JWTCreator.init()
            .withPayload(payload)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry("stringClaim", "string").matches(payloadJson))
        assertTrue(hasEntry("intClaim", 41).matches(payloadJson))
        assertTrue(hasEntry("listClaim", listClaim).matches(payloadJson))
        assertTrue(hasEntry("objClaim", mapClaim).matches(payloadJson))
    }

    @Test
    fun withPayloadShouldSupportNullValuesEverywhere() {
        /*
        JWT:
            {
              "listClaim": [
                "answer to ultimate question of life",
                42,
                null
              ],
              "claim": null,
              "listNestedClaim": [
                1,
                2,
                {
                  "nestedObjKey": null
                }
              ],
              "objClaim": {
                "nestedObjKey": null,
                "objObjKey": {
                  "nestedObjKey": null,
                  "objListKey": [
                    null,
                    "nestedList2"
                  ]
                },
                "objListKey": [
                  null,
                  "nestedList2"
                ]
              }
            }
         */

        val listClaim = listOf("answer to ultimate question of life", 42, null)
        val listNestedClaim = listOf(1, 2, Collections.singletonMap("nestedObjKey", null))
        val objListKey = listOf(null, "nestedList2")
        val objClaim = HashMap<String?, Any?>()

        objClaim["nestedObjKey"] = null
        objClaim["objListKey"] = objListKey
        objClaim["objObjKey"] = HashMap<String?, Any?>(objClaim)

        val payload = buildMap {
            this["claim"] = null
            this["listClaim"] = listClaim
            this["listNestedClaim"] = listNestedClaim
            this["objClaim"] = objClaim
        }

        val jwt = JWTCreator.init()
            .withPayload(payload)
            .withHeader(payload)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()
        val headerJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[0]).decodeToString()

        assertTrue(hasEntry("claim", null).matches(payloadJson))
        assertTrue(hasEntry("listClaim", listClaim).matches(payloadJson))
        assertTrue(hasEntry("listNestedClaim", listNestedClaim).matches(payloadJson))
        assertTrue(hasEntry("objClaim", objClaim).matches(payloadJson))

        assertTrue(hasEntry("claim", null).matches(headerJson))
        assertTrue(hasEntry("listClaim", listClaim).matches(headerJson))
        assertTrue(hasEntry("listNestedClaim", listNestedClaim).matches(headerJson))
        assertTrue(hasEntry("objClaim", objClaim).matches(headerJson))
    }

    @Test
    fun withPayloadShouldSupportJsonValueWithNestedDataStructure() {
        val stringClaim = "someClaim"
        val intClaim = 1
        val nestedListClaims = listOf("1", "2")
        val claimsJson = "{\"stringClaim\": \"someClaim\", \"intClaim\": 1, \"nestedClaim\": { \"listClaim\": [ \"1\", \"2\" ]}}"

        val jwt = JWTCreator.init()
            .withPayload(claimsJson)
            .sign(Algorithm.HMAC256("secret"))

        val parts = jwt.split("\\.".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL).decode(parts[1]).decodeToString()

        assertTrue(hasEntry("stringClaim", stringClaim).matches(payloadJson))
        assertTrue(hasEntry("intClaim", intClaim).matches(payloadJson))
        assertTrue(hasEntry("listClaim", nestedListClaims).matches(payloadJson))
    }

    @Test
    fun shouldFailWithIllegalArgumentExceptionForInvalidJsonForPayloadClaims() {
        val t = assertFailsWith<IllegalArgumentException> {
            JWTCreator.init()
                .withPayload("{ invalidJson }")
                .sign(Algorithm.HMAC256("secret"))
        }

        assertEquals("Invalid payload JSON", t.message)
    }

    @Test
    fun shouldCreatePayloadWithNullForMap() {
        val jwt = JWTCreator.init()
            .withClaim("name", null as MutableMap<String, *>?)
            .sign(Algorithm.HMAC256("secret"))

        assertTrue(JWT.decode(jwt).getClaim("name").isNull)
    }

    @Test
    fun shouldCreatePayloadWithNullForList() {
        val jwt = JWTCreator.init()
            .withClaim("name", null as MutableList<*>?)
            .sign(Algorithm.HMAC256("secret"))

        assertTrue(JWT.decode(jwt).getClaim("name").isNull)
    }

    companion object {
        private const val PRIVATE_KEY_RSA = "src/androidUnitTest/resources/rsa-private.pem"
        private const val PRIVATE_KEY_EC_256 = "src/androidUnitTest/resources/ec256-key-private.pem"
    }
}
