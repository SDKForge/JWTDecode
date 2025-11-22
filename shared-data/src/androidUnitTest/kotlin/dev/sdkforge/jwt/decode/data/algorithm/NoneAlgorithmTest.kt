package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.data.JWT
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class NoneAlgorithmTest {

    @Test
    fun shouldPassNoneVerification() {
        val jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9."

        (Algorithm.NONE as NoneAlgorithm).verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailNoneVerificationWhenTokenHasTwoParts() {
        val jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9"

        val t = assertFailsWith<JWTDecodeException> {
            (Algorithm.NONE as NoneAlgorithm).verify(JWT.decode(jwt))
        }

        assertEquals("The token was expected to have 3 parts, but got 2.", t.message)
    }

    @Test
    fun shouldFailNoneVerificationWhenSignatureIsPresent() {
        val jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss"

        val t = assertFailsWith<SignatureVerificationException> {
            (Algorithm.NONE as NoneAlgorithm).verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: NoneAlgorithm", t.message)
    }

    @Test
    fun shouldReturnNullSigningKeyId() {
        assertNull((Algorithm.NONE as NoneAlgorithm).signingKeyId)
    }

    @Test
    fun shouldThrowWhenSignatureNotValidBase64() {
        val jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvW+iGcCrPqZtbp_4OnQzZXaTfss"

        assertFailsWith<SignatureVerificationException> {
            (Algorithm.NONE as NoneAlgorithm).verify(JWT.decode(jwt))
        }
    }
}
