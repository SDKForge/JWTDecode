package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.PublicKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPrivateKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPublicKey
import dev.sdkforge.jwt.decode.data.JWT
import dev.sdkforge.jwt.decode.data.readPrivateKey
import dev.sdkforge.jwt.decode.data.readPublicKey
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException
import dev.sdkforge.jwt.decode.domain.provider.RSAKeyProvider
import io.mockk.every
import io.mockk.junit4.MockKRule
import io.mockk.mockk
import io.mockk.mockkStatic
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import org.junit.Rule

class RSAAlgorithmTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    // Verify

    @Test
    fun shouldPassRSA256Verification() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA256VerificationWithBothKeys() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(
                PUBLIC_KEY_FILE,
                "RSA",
            ),
            readPrivateKey<RSAPrivateKey>(
                PRIVATE_KEY_FILE,
                "RSA",
            ),
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA256VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.jXrbue3xJmnzWH9kU-uGeCTtgbQEKbch8uHd4Z52t86ncNyepfusl_bsyLJIcxMwK7odRzKiSE9efV9JaRSEDODDBdMeCzODFx82uBM7e46T1NLVSmjYIM7Hcfh81ZeTIk-hITvgtL6hvTdeJWOCZAB0bs18qSVW5SvursRUhY38xnhuNI6HOHCtqp7etxWAu6670L53I3GtXsmi6bXIzv_0v1xZcAFg4HTvXxfhfj3oCqkSs2nC27mHxBmQtmZKWmXk5HzVUyPRwTUWx5wHPT_hCsGer-CMCAyGsmOg466y1KDqf7ogpMYojfVZGWBsyA39LO1oWZ4Ryomkn8t5Vg"

        val publicKey = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA")

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns publicKey.asNativeRSAPublicKey
        }

        val algorithm = Algorithm.RSA256(provider) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailRSA256VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.jXrbue3xJmnzWH9kU-uGeCTtgbQEKbch8uHd4Z52t86ncNyepfusl_bsyLJIcxMwK7odRzKiSE9efV9JaRSEDODDBdMeCzODFx82uBM7e46T1NLVSmjYIM7Hcfh81ZeTIk-hITvgtL6hvTdeJWOCZAB0bs18qSVW5SvursRUhY38xnhuNI6HOHCtqp7etxWAu6670L53I3GtXsmi6bXIzv_0v1xZcAFg4HTvXxfhfj3oCqkSs2nC27mHxBmQtmZKWmXk5HzVUyPRwTUWx5wHPT_hCsGer-CMCAyGsmOg466y1KDqf7ogpMYojfVZGWBsyA39LO1oWZ4Ryomkn8t5Vg"

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }

        val algorithm = Algorithm.RSA256(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailRSA256VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(INVALID_PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", t.message)
    }

    @Test
    fun shouldFailRSA256VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val algorithm = Algorithm.RSA256(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldPassRSA384Verification() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"

        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA384VerificationWithBothKeys() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"

        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA384VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.ITNTVCT7ercumZKHV4-BXGkJwwa7fyF3CnSfEvm09fDFSkaseDxNo_75WLDmK9WM8RMHTPvkpHcTKm4guYEbC_la7RzFIKpU72bppzQojggSmWWXt_6zq50QP2t5HFMebote1zxhp8ccEdSCX5pyY6J2sm9kJ__HKK32KxIVCTjVCz-bFBS60oG35aYEySdKsxuUdWbD5FQ9I16Ony2x0EPvmlL3GPiAPmgjSFp3LtcBIbCDaoonM7iuDRGIQiDN_n2FKKb1Bt4_38uWPtTkwRpNalt6l53Y3JDdzGI5fMrMo3RQnQlAJxUJKD0eL6dRAA645IVIIXucHwuhgGGIVw"

        val publicKey = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA")

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns publicKey.asNativeRSAPublicKey
        }

        val algorithm = Algorithm.RSA384(provider) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailRSA384VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.ITNTVCT7ercumZKHV4-BXGkJwwa7fyF3CnSfEvm09fDFSkaseDxNo_75WLDmK9WM8RMHTPvkpHcTKm4guYEbC_la7RzFIKpU72bppzQojggSmWWXt_6zq50QP2t5HFMebote1zxhp8ccEdSCX5pyY6J2sm9kJ__HKK32KxIVCTjVCz-bFBS60oG35aYEySdKsxuUdWbD5FQ9I16Ony2x0EPvmlL3GPiAPmgjSFp3LtcBIbCDaoonM7iuDRGIQiDN_n2FKKb1Bt4_38uWPtTkwRpNalt6l53Y3JDdzGI5fMrMo3RQnQlAJxUJKD0eL6dRAA645IVIIXucHwuhgGGIVw"

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }

        val algorithm = Algorithm.RSA384(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailRSA384VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"

        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(INVALID_PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA", t.message)
    }

    @Test
    fun shouldFailRSA384VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"

        val algorithm = Algorithm.RSA384(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldPassRSA512Verification() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"

        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA512VerificationWithBothKeys() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"

        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldPassRSA512VerificationWithProvidedPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.GpHv85Q8tAU_6hNWsmO0GEpO1qz9lmK3NKeAcemysz9MGo4FXWn8xbD8NjCfzZ8EWphm65M0NArKSjpKHO5-gcNsQxLBVfSED1vzcoaZH_Vy5Rp1M76dGH7JghB_66KrpfyMxer_yRJb-KXesNvIroDGilLQF2ENG-IfLF5nBKlDiVHmPaqr3pm1q20fNLhegkSRca4BJ5VdIlT6kOqE_ykVyCBqzD_oXp3LKO_ARnxoeB9SegIW1fy_3tuxSTKYsCZiOfiyVEXXblAuY3pSLZnGvgeBRnfvmWXDWhP0vVUFtYJBF09eULvvUMVqWcrjUG9gDzzzT7veiY_fHd_x8g"

        val publicKey = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA")

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns publicKey.asNativeRSAPublicKey
        }

        val algorithm = Algorithm.RSA512(provider) as RSAAlgorithm

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailRSA512VerificationWhenProvidedPublicKeyIsNull() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.GpHv85Q8tAU_6hNWsmO0GEpO1qz9lmK3NKeAcemysz9MGo4FXWn8xbD8NjCfzZ8EWphm65M0NArKSjpKHO5-gcNsQxLBVfSED1vzcoaZH_Vy5Rp1M76dGH7JghB_66KrpfyMxer_yRJb-KXesNvIroDGilLQF2ENG-IfLF5nBKlDiVHmPaqr3pm1q20fNLhegkSRca4BJ5VdIlT6kOqE_ykVyCBqzD_oXp3LKO_ARnxoeB9SegIW1fy_3tuxSTKYsCZiOfiyVEXXblAuY3pSLZnGvgeBRnfvmWXDWhP0vVUFtYJBF09eULvvUMVqWcrjUG9gDzzzT7veiY_fHd_x8g"

        val provider: RSAKeyProvider = mockk {
            every { getPublicKeyById("my-key-id") } returns null
        }

        val algorithm = Algorithm.RSA512(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailRSA512VerificationWithInvalidPublicKey() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"

        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(INVALID_PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA", t.message)
    }

    @Test
    fun shouldFailRSA512VerificationWhenUsingPrivateKey() {
        val jwt =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"

        val algorithm = Algorithm.RSA512(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA", t.message)
        assertEquals("The given Public Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldThrowWhenMacAlgorithmDoesNotExists() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val publicKey: RSAPublicKey = mockk()
        val privateKey: RSAPrivateKey = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey.asNativeRSAPublicKey, privateKey.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                publicKey = any<PublicKey>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)

        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowWhenThePublicKeyIsInvalid() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val publicKey: RSAPublicKey? = mockk()
        val privateKey: RSAPrivateKey? = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                publicKey = any<PublicKey>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws InvalidKeyException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)

        assertIs<InvalidKeyException>(t.cause)
    }

    @Test
    fun shouldThrowWhenTheSignatureIsNotPrepared() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"
        val publicKey: RSAPublicKey? = mockk()
        val privateKey: RSAPrivateKey? = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every {
            verifySignature(
                algorithm = any<String>(),
                publicKey = any<PublicKey>(),
                headerBytes = any<ByteArray>(),
                payloadBytes = any<ByteArray>(),
                signatureBytes = any<ByteArray>(),
            )
        } throws SignatureException()

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: some-algorithm", t.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldDoRSA256Signing() {
        val expectedSignature =
            "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw"

        val algorithmSign = Algorithm.RSA256(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm
        val algorithmVerify = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithmSign,
            RS256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA256SigningWithBothKeys() {
        val expectedSignature =
            "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw"

        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA"),
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA"),
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA256SigningWithProvidedPrivateKey() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey
            every { getPublicKeyById(null) } returns readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey
        }

        val algorithm = Algorithm.RSA256(provider) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS256Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnRSA256SigningWhenProvidedPrivateKeyIsNull() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns null
        }

        val algorithm = Algorithm.RSA256(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnRSA256SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldDoRSA384Signing() {
        val expectedSignature =
            "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ"

        val algorithmSign = Algorithm.RSA384(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val algorithmVerify = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithmSign,
            RS384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA384SigningWithBothKeys() {
        val expectedSignature =
            "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ"

        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA"),
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA"),
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA384SigningWithProvidedPrivateKey() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey
            every { getPublicKeyById(null) } returns readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey
        }

        val algorithm = Algorithm.RSA384(provider) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS384Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnRSA384SigningWhenProvidedPrivateKeyIsNull() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns null
        }

        val algorithm = Algorithm.RSA384(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnRSA384SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldDoRSA512Signing() {
        val expectedSignature =
            "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA"

        val algorithmSign = Algorithm.RSA512(
            readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA").asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val algorithmVerify = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithmSign,
            RS512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithmVerify.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA512SigningWithBothKeys() {
        val expectedSignature =
            "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA"

        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(
                PUBLIC_KEY_FILE,
                "RSA",
            ),
            readPrivateKey<RSAPrivateKey>(
                PRIVATE_KEY_FILE,
                "RSA",
            ),
        ) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)
        assertSignatureValue(jwt, expectedSignature)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldDoRSA512SigningWithProvidedPrivateKey() {
        val rsaPrivateKey = readPrivateKey<RSAPrivateKey>(PRIVATE_KEY_FILE, "RSA")
        val rsaPublicKey = readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA")
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns rsaPrivateKey.asNativeRSAPrivateKey
            every { getPublicKeyById(null) } returns rsaPublicKey.asNativeRSAPublicKey
        }
        val algorithm = Algorithm.RSA512(provider) as RSAAlgorithm

        val jwt: String = asJWT(
            algorithm,
            RS512Header,
            auth0IssPayload,
        )

        assertSignaturePresent(jwt)

        algorithm.verify(JWT.decode(jwt))
    }

    @Test
    fun shouldFailOnRSA512SigningWhenProvidedPrivateKeyIsNull() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns null
        }
        val algorithm = Algorithm.RSA512(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldFailOnRSA512SigningWhenUsingPublicKey() {
        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() {
        val publicKey: RSAPublicKey? = mockk()
        val privateKey: RSAPrivateKey? = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws NoSuchAlgorithmException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<NoSuchAlgorithmException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenThePrivateKeyIsInvalid() {
        val publicKey: RSAPublicKey? = mockk()
        val privateKey: RSAPrivateKey? = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws InvalidKeyException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<InvalidKeyException>(t.cause)
    }

    @Test
    fun shouldThrowOnSignWhenTheSignatureIsNotPrepared() {
        val publicKey: RSAPublicKey? = mockk()
        val privateKey: RSAPrivateKey? = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey?.asNativeRSAPublicKey, privateKey?.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        mockkStatic("dev.sdkforge.jwt.decode.data.algorithm.Crypto_androidKt")
        every { createSignatureFor(any<String>(), any<PrivateKey>(), any<ByteArray>(), any<ByteArray>()) } throws SignatureException()

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0), ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm", t.message)

        assertIs<SignatureException>(t.cause)
    }

    @Test
    fun shouldReturnNullSigningKeyIdIfCreatedWithDefaultProvider() {
        val publicKey: RSAPublicKey = mockk()
        val privateKey: RSAPrivateKey = mockk()
        val provider: RSAKeyProvider = RSAAlgorithm.providerForKeys(publicKey.asNativeRSAPublicKey, privateKey.asNativeRSAPrivateKey)
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider) as RSAAlgorithm

        assertNull(algorithm.signingKeyId)
    }

    @Test
    fun shouldReturnSigningKeyIdFromProvider() {
        val provider: RSAKeyProvider = mockk {
            every { privateKeyId } returns "keyId"
        }
        val algorithm = RSAAlgorithm("some-alg", "some-algorithm", provider)

        assertEquals("keyId", algorithm.signingKeyId)
    }

    @Test
    fun shouldBeEqualSignatureMethodResults() {
        val privateKey = readPrivateKey<RSAPrivateKey>(
            PRIVATE_KEY_FILE,
            "RSA",
        )
        val publicKey = readPublicKey<RSAPublicKey>(
            PUBLIC_KEY_FILE,
            "RSA",
        )

        val algorithm = Algorithm.RSA256(publicKey, privateKey) as RSAAlgorithm

        val header = byteArrayOf(0x00, 0x01, 0x02)
        val payload = byteArrayOf(0x04, 0x05, 0x06)

        val bout = java.io.ByteArrayOutputStream()
        bout.write(header)
        bout.write('.'.code)
        bout.write(payload)

        assertContentEquals(algorithm.sign(header, payload), algorithm.sign(bout.toByteArray()))
    }

    /**
     * Test deprecated signing method error handling.
     *
     * @see {@linkplain .shouldFailOnRSA256SigningWhenProvidedPrivateKeyIsNull}
     */
    @Test
    fun shouldFailOnRSA256SigningWithDeprecatedMethodWhenProvidedPrivateKeyIsNull() {
        val provider: RSAKeyProvider = mockk {
            every { privateKey } returns null
        }
        val algorithm = Algorithm.RSA256(provider) as RSAAlgorithm

        val t = assertFailsWith<SignatureGenerationException> {
            algorithm.sign(ByteArray(0))
        }

        assertEquals("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA", t.message)
        assertEquals("The given Private Key is null.", t.cause?.message)

        assertIs<IllegalStateException>(t.cause)
    }

    @Test
    fun shouldThrowWhenSignatureNotValidBase64() {
        val jwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNu+LAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"
        val algorithm = Algorithm.RSA256(
            readPrivateKey<RSAPrivateKey>(
                PRIVATE_KEY_FILE,
                "RSA",
            ).asNativeRSAPrivateKey,
        ) as RSAAlgorithm

        val t = assertFailsWith<SignatureVerificationException> {
            algorithm.verify(JWT.decode(jwt))
        }

        assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", t.message)

        assertIs<IllegalArgumentException>(t.cause)
    }

    @Suppress("ktlint:standard:property-naming")
    companion object {
        private const val PRIVATE_KEY_FILE = "src/androidUnitTest/resources/rsa-private.pem"
        private const val PUBLIC_KEY_FILE = "src/androidUnitTest/resources/rsa-public.pem"
        private const val INVALID_PUBLIC_KEY_FILE = "src/androidUnitTest/resources/rsa-public_invalid.pem"

        // Sign
        private const val RS256Header = "eyJhbGciOiJSUzI1NiJ9"
        private const val RS384Header = "eyJhbGciOiJSUzM4NCJ9"
        private const val RS512Header = "eyJhbGciOiJSUzUxMiJ9"
        private const val auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9"
    }
}
