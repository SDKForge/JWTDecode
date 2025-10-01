package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlinx.serialization.ExperimentalSerializationApi

@OptIn(ExperimentalTime::class, ExperimentalSerializationApi::class)
class JWTParserTest {
    private val parser: dev.sdkforge.jwt.decode.domain.JWTParser = JWTParser

    @Test
    fun shouldParsePayload() {
        assertEquals(JWTPayload(), parser.parsePayload("{}"))
    }

    @Test
    fun shouldThrowOnInvalidPayload() {
        val jsonPayload = "{{"

        val t = assertFailsWith<JWTDecodeException> {
            parser.parsePayload(jsonPayload)
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }

    @Test
    fun shouldParseHeader() {
        JWTParser.parseHeader("{}")
    }

    @Test
    fun shouldThrowOnInvalidHeader() {
        val jsonHeader = "}}"

        val t = assertFailsWith<JWTDecodeException> {
            parser.parseHeader(jsonHeader)
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }

    @Test
    fun shouldThrowWhenConvertingHeaderFromInvalidJson() {
        val t = assertFailsWith<JWTDecodeException> {
            parser.parseHeader("}{")
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }

    @Test
    fun shouldThrowWhenConvertingPayloadFromInvalidJson() {
        val t = assertFailsWith<JWTDecodeException> {
            parser.parsePayload("}{")
        }

        assertTrue { t.message?.startsWith("Unexpected JSON token") == true }
    }
}
