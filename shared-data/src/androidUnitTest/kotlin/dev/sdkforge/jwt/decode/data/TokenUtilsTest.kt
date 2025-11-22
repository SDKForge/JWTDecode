package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TokenUtilsTest {

    @Test
    fun toleratesEmptyFirstPart() {
        val token = ".eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"
        val parts = TokenUtils.splitToken(token)

        assertEquals(3, parts.size)
        assertEquals("", parts[0])
        assertEquals("eyJpc3MiOiJhdXRoMCJ9", parts[1])
        assertEquals("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc", parts[2])
    }

    @Test
    fun toleratesEmptySecondPart() {
        val token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"
        val parts = TokenUtils.splitToken(token)

        assertEquals(3, parts.size)
        assertEquals("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", parts[0])
        assertEquals("", parts[1])
        assertEquals("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc", parts[2])
    }

    @Test
    fun shouldSplitToken() {
        val token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"
        val parts = TokenUtils.splitToken(token)

        assertEquals(3, parts.size)
        assertEquals("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", parts[0])
        assertEquals("eyJpc3MiOiJhdXRoMCJ9", parts[1])
        assertEquals("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc", parts[2])
    }

    @Test
    fun shouldSplitTokenWithEmptySignature() {
        val token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9."
        val parts = TokenUtils.splitToken(token)

        assertEquals(3, parts.size)
        assertEquals("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", parts[0])
        assertEquals("eyJpc3MiOiJhdXRoMCJ9", parts[1])
        assertEquals(0, parts[2].length)
    }

    @Test
    fun shouldThrowOnSplitTokenWithMoreThan3Parts() {
        val t = assertFailsWith<JWTDecodeException> {
            TokenUtils.splitToken("this.has.four.parts")
        }

        assertEquals("The token was expected to have 3 parts, but got 4.", t.message)
    }

    @Test
    fun shouldThrowOnSplitTokenWithNoParts() {
        val t = assertFailsWith<JWTDecodeException> {
            TokenUtils.splitToken("notajwt")
        }

        assertEquals("The token was expected to have 3 parts, but got 1.", t.message)
    }

    @Test
    fun shouldThrowOnSplitTokenWith2Parts() {
        val t = assertFailsWith<JWTDecodeException> {
            TokenUtils.splitToken("two.parts")
        }

        assertEquals("The token was expected to have 3 parts, but got 2.", t.message)
    }

    @Test
    fun shouldThrowOnSplitTokenWithNullValue() {
        val t = assertFailsWith<JWTDecodeException> {
            TokenUtils.splitToken(null)
        }

        assertEquals("The token is null.", t.message)
    }
}
