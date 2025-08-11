package dev.sdkforge.jwt.decode.core

interface Platform {
    val name: String
    val version: String
}

expect val currentPlatform: Platform
