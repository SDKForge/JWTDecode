@file:Suppress("ktlint:standard:function-signature", "ktlint:standard:class-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.crypto.domain.ec.asNativeECPublicKey
import dev.sdkforge.crypto.domain.rsa.asNativeRSAPublicKey
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA256
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA384
import dev.sdkforge.jwt.decode.data.algorithm.ECDSA512
import dev.sdkforge.jwt.decode.data.algorithm.HMAC256
import dev.sdkforge.jwt.decode.data.algorithm.HMAC384
import dev.sdkforge.jwt.decode.data.algorithm.HMAC512
import dev.sdkforge.jwt.decode.data.algorithm.RSA256
import dev.sdkforge.jwt.decode.data.algorithm.RSA384
import dev.sdkforge.jwt.decode.data.algorithm.RSA512
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.JWTVerifier
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import io.mockk.junit4.MockKRule
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Collections
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import net.jodah.concurrentunit.Waiter
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class ConcurrentVerifyTest {

    @get:Rule
    val mockkRule = MockKRule(this)

    private var executor: ExecutorService? = null

    @Before
    fun setUp() {
        executor = Executors.newFixedThreadPool(THREAD_COUNT)
    }

    @After
    fun shutDown() {
        executor!!.shutdown()
    }

    @Throws(TimeoutException::class, InterruptedException::class)
    private fun concurrentVerify(verifier: JWTVerifier, token: String) {
        val waiter = Waiter()
        val tasks = Collections.nCopies(REPEAT_COUNT, VerifyTask(waiter, verifier, token))

        executor!!.invokeAll<DecodedJWT?>(tasks, TIMEOUT, TimeUnit.MILLISECONDS)

        waiter.await(TIMEOUT, REPEAT_COUNT)
    }

    private class VerifyTask(
        private val waiter: Waiter,
        private val verifier: JWTVerifier,
        private val token: String,
    ) : Callable<DecodedJWT?> {

        override fun call(): DecodedJWT? {
            var jwt: DecodedJWT? = null

            try {
                jwt = verifier.verify(token)
                waiter.assertNotNull(jwt)
            } catch (e: Exception) {
                waiter.fail(e)
            }

            waiter.resume()

            return jwt
        }
    }

    @Test
    fun shouldPassHMAC256Verification() {
        val token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M"

        val algorithm = Algorithm.HMAC256("secret")
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassHMAC384Verification() {
        val token =
            "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw"

        val algorithm = Algorithm.HMAC384("secret")
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassHMAC512Verification() {
        val token =
            "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw"

        val algorithm = Algorithm.HMAC512("secret")
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassRSA256Verification() {
        val token =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA"

        val algorithm = Algorithm.RSA256(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        )
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassRSA384Verification() {
        val token =
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw"
        val algorithm = Algorithm.RSA384(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        )

        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassRSA512Verification() {
        val token =
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow"
        val algorithm = Algorithm.RSA512(
            readPublicKey<RSAPublicKey>(PUBLIC_KEY_FILE, "RSA").asNativeRSAPublicKey,
        )
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassECDSA256VerificationWithJOSESignature() {
        val token =
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g"

        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_256, "EC")
        val algorithm = Algorithm.ECDSA256(key.asNativeECPublicKey)
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassECDSA384VerificationWithJOSESignature() {
        val token =
            "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z"

        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_384, "EC")
        val algorithm = Algorithm.ECDSA384(key.asNativeECPublicKey)
        val verifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    @Test
    fun shouldPassECDSA512VerificationWithJOSESignature() {
        val token =
            "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2"

        val key = readPublicKey<ECPublicKey>(PUBLIC_KEY_FILE_512, "EC")
        val algorithm = Algorithm.ECDSA512(key.asNativeECPublicKey)
        val verifier: JWTVerifier = dev.sdkforge.jwt.decode.data.JWTVerifier.init(algorithm).withIssuer("auth0").build()

        concurrentVerify(verifier, token)
    }

    companion object {
        private const val TIMEOUT = (10 * 1000 * 1000).toLong() // 1 min
        private const val THREAD_COUNT = 100
        private const val REPEAT_COUNT = 1000
        private const val PUBLIC_KEY_FILE = "src/androidUnitTest/resources/rsa-public.pem"
        private const val PUBLIC_KEY_FILE_256 = "src/androidUnitTest/resources/ec256-key-public.pem"
        private const val PUBLIC_KEY_FILE_384 = "src/androidUnitTest/resources/ec384-key-public.pem"
        private const val PUBLIC_KEY_FILE_512 = "src/androidUnitTest/resources/ec512-key-public.pem"
    }
}
