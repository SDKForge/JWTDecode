package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Header
import kotlin.test.Test
import kotlin.test.assertEquals

class HeaderDeserializerTest {

    @Test
    fun shouldNotRemoveKnownPublicClaimsFromTree() {
        val headerJSON = "{\n" +
            "  \"alg\": \"HS256\",\n" +
            "  \"typ\": \"jws\",\n" +
            "  \"cty\": \"content\",\n" +
            "  \"kid\": \"key\",\n" +
            "  \"roles\": \"admin\"\n" +
            "}"
        val header: Header = JWTParser.parseHeader(headerJSON)

        assertEquals("HS256", header.algorithm)
        assertEquals("jws", header.type)
        assertEquals("content", header.contentType)
        assertEquals("key", header.keyId)

        assertEquals("admin", header.getHeaderClaim("roles").asString())
        assertEquals("HS256", header.getHeaderClaim("alg").asString())
        assertEquals("jws", header.getHeaderClaim("typ").asString())
        assertEquals("content", header.getHeaderClaim("cty").asString())
        assertEquals("key", header.getHeaderClaim("kid").asString())
    }
}
