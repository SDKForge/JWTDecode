package dev.sdkforge.jwt.decode.core

actual val currentPlatform: Platform = object : Platform {
    override val name: String get() = "Android"
    override val version: String get() = android.os.Build.VERSION.SDK_INT.toString()
}
