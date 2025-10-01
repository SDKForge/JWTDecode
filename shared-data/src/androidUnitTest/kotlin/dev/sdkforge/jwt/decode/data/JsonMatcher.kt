@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import java.lang.reflect.Array
import org.hamcrest.Description
import org.hamcrest.Matcher
import org.hamcrest.TypeSafeDiagnosingMatcher

class JsonMatcher private constructor(
    private val key: String,
    value: Any?,
    private val matcher: Matcher<*>?,
) : TypeSafeDiagnosingMatcher<String?>() {

    private val entry: String? = if (value != null) getStringKey(key) + objectToString(value) else null

    override fun matchesSafely(item: String?, mismatchDescription: Description): Boolean {
        if (item == null) {
            mismatchDescription.appendText("JSON was null")
            return false
        }
        if (matcher != null) {
            if (!matcher.matches(item)) {
                matcher.describeMismatch(item, mismatchDescription)
                return false
            }
            if (!item.contains(getStringKey(key))) {
                mismatchDescription.appendText("JSON didn't contained the key ").appendValue(key)
                return false
            }
        }
        if (entry != null && !item.contains(entry)) {
            mismatchDescription.appendText("JSON was ").appendValue(item)
            return false
        }

        return true
    }

    override fun describeTo(description: Description) {
        if (matcher == null) {
            description.appendText("A JSON with entry ").appendValue(entry)
        } else {
            matcher.describeTo(description)
        }
    }

    private fun getStringKey(key: String): String = "\"$key\":"

    private fun objectToString(value: Any?): String = when (value) {
        null -> "null"
        is String -> "\"" + value + "\""
        is MutableMap<*, *> -> mapToString(value as MutableMap<String?, Any?>)
        is Array -> arrayToString(value as kotlin.Array<Any?>)
        is MutableList<*> -> listToString(value as MutableList<Any?>)
        else -> value.toString()
    }

    private fun arrayToString(array: kotlin.Array<Any?>): String {
        val sb = StringBuilder()
        sb.append("[")
        for (i in array.indices) {
            val o = array[i]
            sb.append(objectToString(o))
            if (i + 1 < array.size) {
                sb.append(",")
            }
        }
        sb.append("]")
        return sb.toString()
    }

    private fun listToString(list: MutableList<Any?>): String {
        val sb = StringBuilder()
        sb.append("[")
        val it = list.iterator()
        while (it.hasNext()) {
            val o = it.next()
            sb.append(objectToString(o))
            if (it.hasNext()) {
                sb.append(",")
            }
        }
        sb.append("]")
        return sb.toString()
    }

    private fun mapToString(map: MutableMap<String?, Any?>): String {
        val sb = StringBuilder()
        sb.append("{")
        val it = map.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            sb.append("\"" + e.key + "\":" + objectToString(e.value))
            if (it.hasNext()) {
                sb.append(",")
            }
        }
        sb.append("}")
        return sb.toString()
    }

    companion object {
        fun hasEntry(key: String, value: Any?): JsonMatcher = JsonMatcher(key, value, null)
        fun hasEntry(key: String, valueMatcher: Matcher<*>?): JsonMatcher = JsonMatcher(key, null, valueMatcher)
        fun isNotPresent(key: String): JsonMatcher = JsonMatcher(key, null, null)
    }
}
